/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2014 Joyent Inc. All rights reserved
 */

#include <sys/lx_brand.h>
#include <sys/proc.h>
#include <sys/signal.h>
#include <sys/fault.h>
#include <sys/errno.h>
#include <lx_signum.h>
#include <sys/procfs.h>
#include <sys/thread.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/lx_pid.h>
/*
 * This is the completely in kernel implementation of ptrace for lx brands. It
 * will present a few interfaces that others may use:
 *
 * lx_ptrace: the function that user code calls to activate various tracing
 * function. ptrace(2) leads to a call to this.  
 *
 * lx_tracepoint(type, ...):
 * These will be support for ptrace events, we can insert them as calls into
 * other syscalls. the type will be an enum of some kind to check against
 * enabled event flags.
 *
 * ptracing is an action where the tracer is a lwp and the tracee is a process.
 * The tracer waits on the process in addition to any children of the normal
 * process it has. there may be only one tracer for any given process, but each
 * lwp within that process may be either traced or not traced.
 * 
 */

static long
ptrace_traceme(void)
{
	lx_proc_data_t *lxpd = ttolxproc(curthread);
	proc_t p = curproc;
	sigset_t signals;
	fltset_t flts;

	if (p->p_brand != &lx_brand)
		return (set_errno(EPERM));
	if (ttolxlwp(t) == NULL)
		return (set_errno(EPERM));

	mutex_enter(&p->p_lock);
	if(lxpd->l_tracer_pid != 0) {
		mutex_exit(&p->p_lock);
		return (set_errno(EPERM));
	}

	ASSERT(ttolxlwp(curthread)->br_pid != 0);
	lxpd->l_tracer_pid = ttolxlwp(curthread)->br_pid;
	p->p_proc_flag |= P_PR_TRACE;
	p->p_proc_flag |= P_PR_PTRACE;
	p->p_proc_flag &= ~P_PR_FORK;

	prfillset(&signals);
	prdelset(&signals);
	prassignset(&p->p_sigmask, signals);

	premptyset(&flts);
	prassignset(&p->fltmask, &flts);
	mutex_exit(&p->p_lock);
}

static long
ptrace_attach(pid_t pid, pid_t s_pid, id_t s_tid)
{
	proc_t *cp;
	proc_t *pp = curproc;
	lx_proc_data_t *lxpd;
	int err = 0;
	lx_lwp_data_t *lxlwpd = ttolxlwp(curthread);
	kthread_t *t;

	mutex_enter(&pidlock);
	cp = prfind(s_pid);
	if (cp == NULL) {
		mutex_exit(&pidlock);
		return (set_errno(ESRCH));
	}
	mutex_enter(&cp->p_lock);
	mutex_enter(&pp->p_lock);
	mutex_exit(&pidlock);
	lxpd = ptolxproc(cp);
	if (cp->p_brand != &lx_brand || lxpd == NULL) {
		err = EPERM;
		goto end;
	}
	if (lxpd->l_tracer_pid != 0 || lxlwpd == NULL) {
		err = EPERM;
		goto end;
	}

	t = idtot(cp, s_tid);
	if (t == NULL || ttolxlwp(t)->br_ptrace != 0) {
		err = EPERM;
		goto end;
	}

	/* if acquiring a child of ours, easy */
	if (cp->p_parent == pp) {
		lxpd->l_tracer_pid = lxlwpd->br_pid;
	} else {
	/* Acquiring something not our child requires more bookkeeping. */
		lxpd->l_tracer_pid = lxlwpd->br_pid;
		/* Add to our trace list at the beginning if it exists, otherwise make the list. */
		if (lxlwpd->br_trace_list != NULL) {
			proc_t *head = lxlwpd->br_trace_list;
			lx_proc_data_t *lxhead = ptolxproc(head);

			ASSERT(lxhead->l_trace_prev == NULL);
			lxhead->l_trace_prev = cp;
			lxpd->l_trace_next = head;
			lxlwpd->br_trace_list = cp;
		} else {
			lxlwpd->br_trace_list = cp;
		}
	}
	ttolxlwp(t)->br_ptrace = 1;

end:
	mutex_exit(&cp->p_lock);
	mutex_exit(&pp->p_lock);
	return (err == 0 ? 0 : set_errno(err));

}

/*
 * finds the given solaris pid and uses an outarg to return the proc_t.
 * errors on the following conditions:
 *	- the given pid is not a process
 *	- the given pid is not an lx branded process
 *	- the given pid is not being traced by the caller
 */
static int
acquire_and_validate_proc(pid_t s_pid, proc_t **p)
{
	proc_t *cp;
	lx_proc_data_t *lxpd;
	int err = 0;

	mutex_enter(&pidlock);
	cp = prfind(s_pid);
	if (cp == NULL) {
		mutex_exit(&pidlock);
		return (ESRCH);
	}
	mutex_enter(&cp->p_lock);
	mutex_exit(&pidlock);
	lxpd = ptolxproc(cp);
	if (cp->p_brand != &lx_brand || lxpd == NULL) {
		err = EPERM;
		goto end;
	}
	if (lxpd->l_tracer_pid != curproc->p_pid) {
		err = EPERM;
		goto end;
	}
	*p = cp;
	return (0);
end:
	mutex_exit(&cp->p_lock);
	return (err);
}

static int
acquire_and_validate_lwp(proc_t *p, id_t s_tid, kthread_t **out)
{
	kthread_t *t;
	lx_lwp_data_t *lxlwp;
	
	if ((t = idtot(p, s_tid)) == NULL)
		return (ESRCH);
	lxlwp = ttolxlwp(t);
	if (lxlwp == NULL || lxlwp->br_ptrace != 1)
		return (EPERM);

	*out = t;
	return (0);
}

static long
ptrace_peek(pid_t s_pid, long addr, void *data)
{
	proc_t *cp;
	long k_data;
	int err;

	if (err = acquire_and_validate_proc(s_pid, &cp))
		return (set_errno(err));

	err = uread(cp, &k_data, sizeof (k_data), addr);
	if (err)
		return (seterrno(err));
	err = copyout(k_data, data, sizeof (k_data));
	if(err)
		return (set_errno(EFAULT));
	
	return (0);
}

static long
ptrace_poke(pid_t s_pid, long addr, void *data)
{
	proc_t *cp;
	long k_data;
	int err;
	
	if (err = acquire_and_validate_proc(s_pid, &cp))
		return (set_errno(err));


	if (cp == NULL)
		return (set_errno(ESRCH));

	err = copyin(data, k_data, sizeof (k_data));
	if(err)
		return (set_errno(EFAULT));
	err = uwrite(cp, &k_data, sizeof (k_data), addr);
	if (err)
		return (seterrno(err));
	
	return (0);
}

static long
ptrace_cont(pid_t pid, pid_t s_pid, id_t s_tid int data)
{
	proc_t *p;
	kthread_t *t;
	klwp_t *lwp;
	int sig = ltos_signo[data];
	int err;

	if ((err = acquire_and_validate_proc(pid, &p)) != 0)
		return (set_errno(err));
	if ((err = acquire_and_validate_lwp(p, s_tid, &t)) != 0)
		return (set_errno(err));

	if (sig < 0 || sig >= LX_NSIG)
		return (set_errno(EINVAL));

	/* 
	 *  If the signal is something we want to send it shouldn't go through
	 *  the normal send/recieved path, because that would cause us to
	 *  simply intercept the signal again. rather we should directly swap
	 *  the current signal with whatever we decide to send instead and let
	 *  the tracee continue.
	 *  This conditional basically emulates the PCSSIG command from /proc
	 */
	mutex_enter(&p->p_lock);
	if (sig != 0 && sig != SIGSTOP) {
		kthread_t *tx;
		sigqueue_t *sqp;
		siginfo_t sip;
		sip.si_signo = sig;

		lwp = ttolwp(t);
		/* drop p_lock to do kmem_alloc(KM_SLEEP) */
		mutex_exit(&p->p_lock);
		sqp = kmem_zalloc(sizeof (sigqueue_t), KM_SLEEP);
		mutex_enter(&p->p_lock);

		if (lwp->lwp_curinfo == NULL)
			lwp->lwp_curinfo = sqp;
		else
			kmem_free(sqp, sizeof (sigqueue_t));
		/*
		 * Copy contents of info to current siginfo_t.
		 */
		bcopy(&sip, &lwp->lwp_curinfo->sq_info,
		    sizeof (lwp->lwp_curinfo->sq_info));
		
		/* 
		 * Signal originates from ptrace, the zone of the process being
		 * traced seems as good a place as any 
		 */
		lwp->lwp_curinfo->sq_info.si_zoneid =
		    p->p_zone->zone_id;
		/*
		 * Side-effects for SIGKILL and jobcontrol signals.
		 */
		if (sig == SIGKILL) {
			p->p_flag |= SKILLED;
			p->p_flag &= ~SEXTKILLED;
		} else if (sig == SIGCONT) {
			p->p_flag |= SSCONT;
			sigdelq(p, NULL, SIGSTOP);
			sigdelq(p, NULL, SIGTSTP);
			sigdelq(p, NULL, SIGTTOU);
			sigdelq(p, NULL, SIGTTIN);
			sigdiffset(&p->p_sig, &stopdefault);
			sigdiffset(&p->p_extsig, &stopdefault);
			if ((tx = p->p_tlist) != NULL) {
				do {
					sigdelq(p, tx, SIGSTOP);
					sigdelq(p, tx, SIGTSTP);
					sigdelq(p, tx, SIGTTOU);
					sigdelq(p, tx, SIGTTIN);
					sigdiffset(&tx->t_sig, &stopdefault);
					sigdiffset(&tx->t_extsig, &stopdefault);
				} while ((tx = tx->t_forw) != p->p_tlist);
			}
		} else if (sigismember(&stopdefault, sig)) {
			if (PTOU(p)->u_signal[sig-1] == SIG_DFL &&
			    (sig == SIGSTOP || !p->p_pgidp->pid_pgorphaned))
				p->p_flag &= ~SSCONT;
			sigdelq(p, NULL, SIGCONT);
			sigdelset(&p->p_sig, SIGCONT);
			sigdelset(&p->p_extsig, SIGCONT);
			if ((tx = p->p_tlist) != NULL) {
				do {
					sigdelq(p, tx, SIGCONT);
					sigdelset(&tx->t_sig, SIGCONT);
					sigdelset(&tx->t_extsig, SIGCONT);
				} while ((tx = tx->t_forw) != p->p_tlist);
			}
		}
		thread_lock(t);
		if (ISWAKEABLE(t) || ISWAITING(t)) {
			/* Set signaled sleeping/waiting lwp running */
			setrun_locked(t);
		} else if (t->t_state == TS_STOPPED && sig == SIGKILL) {
			/* If SIGKILL, set stopped lwp running */
			p->p_stopsig = 0;
			t->t_schedflag |= TS_XSTART | TS_PSTART;
			t->t_dtrace_stop = 0;
			setrun_locked(t);
		}
		t->t_sig_check = 1;	/* so ISSIG will be done */
		thread_unlock(t);
		/*
		 * More jobcontrol side-effects.
		 */
		if (sig == SIGCONT && (tx = p->p_tlist) != NULL) {
			p->p_stopsig = 0;
			do {
				thread_lock(tx);
				if (tx->t_state == TS_STOPPED &&
				    tx->t_whystop == PR_JOBCONTROL) {
					tx->t_schedflag |= TS_XSTART;
					setrun_locked(tx);
				}
				thread_unlock(tx);
			} while ((tx = tx->t_forw) != p->p_tlist);
		}
	} else if (sig == 0) {
		lwp->lwp_sig = 0;
		lwp->lwp_extsig = 0;
		/*
		 * Discard current siginfo_t, if any.
		 */
		if (lwp->lwp_curinfo) {
			siginfofree(lwp->lwp_curinfo);
			lwp->lwp_curinfo = NULL;
		}
	}
	mutex_exit(&p->p_lock);

	/* now have to emulate the effects of PCRUN */
	thread_lock(t);
	if ((!ISTOPPED(t) && !VSTOPPED(t) &&
	    !(t->t_proc_flag & TP_PRSTOP)) ||
	    (p->p_agenttp != NULL &&
	    (t != p->p_agenttp))) {
		thread_unlock(t);
		return (set_errno(EBUSY));
	}
	if (ISTOPPED(t)) {
		t->t_schedflag |= TS_PSTART;
		t->t_dtrace_stop = 0;
		setrun_locked(t);
	} else {
		return (set_errno(EINVAL));
	}
	thread_unlock(t);


}

static long
ptrace_setoptions(s_pid, int opts)
{
	proc_t *p;
	lx_proc_data_t *lxpd;
	int err;
	
	if ((err = acquire_and_validate_proc(s_pid, &p)) != 0)
		return (set_errno(err));

	lxpd = ptolxlwp(p);	
	lxpd->l_ptrace_opts = opts;
	return (0);
}

long
lx_ptrace(long request, long pid, unsigned long addr, unsigned long data)
{
	pid_t l_pid = (pid_t)pid;
	pid_t s_pid;
	id_t s_tid;

	if (request != LX_PTRACE_TRACME)
		if (lx_lpid_to_spair(l_pid, &s_pid, &s_tid) < 0)
			return (set_errno(ESRCH));
	switch (request) {
	case LX_PTRACE_TRACEME:
		return (ptrace_traceme());

	case LX_PTRACE_PEEKTEXT:
	case LX_PTRACE_PEEKDATA:
		return (ptrace_peek(s_pid, addr, (int *)data));

	case LX_PTRACE_POKETEXT:
	case LX_PTRACE_POKEDATA:
		return (ptrace_poke(s_pid, addr, (int)data));

	case LX_PTRACE_PEEKUSER:
		return (ptrace_peek_user(s_pid, s_tid, addr, (int *)data));

	case LX_PTRACE_POKEUSER:
		return (ptrace_poke_user(s_pid, s_tid, addr, (int)data));

	case LX_PTRACE_CONT:
		return (ptrace_cont(pid, s_pid, s_tid, (int)data, 0));

	case LX_PTRACE_SINGLESTEP:
		return (ptrace_step(pid, s_pid, s_tid, (int)data));

	case LX_PTRACE_GETREGS:
		return (ptrace_getregs(s_pid, s_tid, data));

	case LX_PTRACE_SETREGS:
		return (ptrace_setregs(s_pid, s_tid, data));

	case LX_PTRACE_GETFPREGS:
		return (ptrace_getfpregs(s_pid, s_tid, data));

	case LX_PTRACE_SETFPREGS:
		return (ptrace_setfpregs(s_pid, s_tid, data));

	case LX_PTRACE_ATTACH:
		return (ptrace_attach(pid, s_pid, s_tid));

	case LX_PTRACE_DETACH:
		return (ptrace_detach(pid, s_pid, s_tid, (int)data));

	case LX_PTRACE_GETFPXREGS:
		return (ptrace_getfpxregs(s_pid, s_tid, data));

	case LX_PTRACE_SETFPXREGS:
		return (ptrace_setfpxregs(s_pid, s_tid, data));

	case LX_PTRACE_SYSCALL:
		return (ptrace_syscall(pid, s_pid, s_tid, (int)data));

	case LX_PTRACE_SETOPTIONS:
		return (ptrace_setoptions(s_pid, (int)data));

	default:
		return (-EINVAL);
	}
}

static boolean_t
ptrace_event_to_marker(int event, int *ret)
{
	switch (option) {
	case LX_PTRACE_O_TRACEFORK:
		*ret = LX_PTRACE_EVENT_FORK;
		break;
	case LX_PTRACE_O_TRACEVFORK:
		*ret = LX_PTRACE_EVENT_VFORK;
		break;
	case LX_PTRACE_O_TRACECLONE:
		*ret = LX_PTRACE_EVENT_CLONE;
		break;
	case LX_PTRACE_O_TRACEEXEC:
		*ret = LX_PTRACE_EVENT_EXEC;
		break;
	case LX_PTRACE_O_TRACEVFORKDONE:
		*ret = LX_PTRACE_EVENT_VFORK_DONE;
		break;
	case LX_PTRACE_O_TRACEEXIT:
		*ret = LX_PTRACE_EVENT_EXIT;
		break;
	case LX_PTRACE_O_TRACESECCOMP:
		*ret = LX_PTRACE_EVENT_SECCOMP;
		break;
	default:
		return (B_FALSE);
	}
	return (B_TRUE);
}

int
lx_ptrace_breakpoint(int event)
{
	proc_t *p = curproc;
	lx_proc_data_t lxpd = ptolxproc(p);

	if (event & lxpd->l_ptrace_opts) {
		if (ptrace_event_to_marker(event, &lxpd->l_ptrace_event) != B_TRUE)
			return (set_errno(EINVAL));

		/* XXX: figure out if we need to actually signal ourselves, or just stop somehow */
		psignal(p, SIGTRAP);

		/*
		 * Since we're stopping, we need to post the SIGCHLD to the parent.
		 * The code in sigcld expects the following two process values to be
		 * setup specifically before it can send the signal, so do that here.
		 */
		sqp = kmem_zalloc(sizeof (sigqueue_t), KM_SLEEP);
		mutex_enter(&pidlock);
		p->p_wdata = SIGTRAP;
		/* CLD_STOPPED is used here to get around the assert in sigcld */
		p->p_wcode = CLD_STOPPED;
		sigcld(p, sqp);
		mutex_exit(&pidlock);

		/* this is what we actually want */
		p->p_wcode = CLD_TRAPPED;
	}
	return (0);
}
