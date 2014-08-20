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
#include <sys/brand.h>
#include <fs/proc/prdata.h>
#include <lx_syscall.h>
#include <sys/panic.h>
#include <sys/cmn_err.h>
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
/* 
 * structs that help format data the ptrace system might ask for 
 * XXX: figure out which of these we actually need
 */
/*
 * This corresponds to the user_i387_struct Linux structure.
 */
typedef struct lx_user_fpregs {
	int lxuf_cwd;
	int lxuf_swd;
	int lxuf_twd;
	int lxuf_fip;
	int lxuf_fcs;
	int lxuf_foo;
	int lxuf_fos;
	int lxuf_st_space[20];
} lx_user_fpregs_t;

/*
 * This corresponds to the user_fxsr_struct Linux structure.
 */
typedef struct lx_user_fpxregs {
	uint16_t lxux_cwd;
	uint16_t lxux_swd;
	uint16_t lxux_twd;
	uint16_t lxux_fop;
	int lxux_fip;
	int lxux_fcs;
	int lxux_foo;
	int lxux_fos;
	int lxux_mxcsr;
	int lxux_reserved;
	int lxux_st_space[32];
	int lxux_xmm_space[32];
	int lxux_padding[56];
} lx_user_fpxregs_t;

/*
 * This corresponds to the user_regs_struct Linux structure.
 */
typedef struct lx_user_regs {
	int lxur_ebx;
	int lxur_ecx;
	int lxur_edx;
	int lxur_esi;
	int lxur_edi;
	int lxur_ebp;
	int lxur_eax;
	int lxur_xds;
	int lxur_xes;
	int lxur_xfs;
	int lxur_xgs;
	int lxur_orig_eax;
	int lxur_eip;
	int lxur_xcs;
	int lxur_eflags;
	int lxur_esp;
	int lxur_xss;
} lx_user_regs_t;


/* 
 * the two pointers in this struct should only be 4 bytes, but are 8 instead,
 * 64 bit will fix this 
 */
typedef struct lx_user {
	lx_user_regs_t lxu_regs;
	int lxu_fpvalid;
	lx_user_fpregs_t lxu_i387;
	uint_t lxu_tsize;
	uint_t lxu_dsize;
	uint_t lxu_ssize;
	uint_t lxu_start_code;
	uint_t lxu_start_stack;
	int lxu_signal;
	int lxu_reserved;
	lx_user_regs_t *lxu_ar0;
	lx_user_fpregs_t *lxu_fpstate;
	uint_t lxu_magic;
	char lxu_comm[32];
	int lxu_debugreg[8];
} lx_user_t;

typedef struct ptrace_monitor_map {
	struct ptrace_monitor_map *pmm_next;	/* next pointer */
	pid_t pmm_monitor;			/* monitor child process */
	pid_t pmm_target;			/* traced Linux pid */
	pid_t pmm_pid;				/* Solaris pid */
	lwpid_t pmm_lwpid;			/* Solaris lwpid */
	uint_t pmm_exiting;			/* detached */
} ptrace_monitor_map_t;

typedef struct ptrace_state_map {
	struct ptrace_state_map *psm_next;	/* next pointer */
	pid_t		psm_pid;		/* Solaris pid */
	uintptr_t	psm_debugreg[8];	/* debug registers */
} ptrace_state_map_t;


static long
ptrace_traceme(void)
{
	lx_proc_data_t *lxpd = ttolxproc(curthread);
	proc_t *p = curproc;
	sigset_t signals;
	fltset_t flts;
	proc_t *pp = p->p_parent;
	lx_lwp_data_t *lwpd = ttolxlwp(curthread);

	if (p->p_brand != &lx_brand)
		return (set_errno(EPERM));
	if (ttolxlwp(curthread) == NULL)
		return (set_errno(EPERM));

	mutex_enter(&p->p_lock);
	if (lxpd->l_tracer_pid != 0) {
		mutex_exit(&p->p_lock);
		return (set_errno(EPERM));
	}

	if (pp->p_brand != &lx_brand || ptolxproc(pp) == NULL) {
		mutex_exit(&p->p_lock);
		return (set_errno(EPERM));
	}

	ASSERT(ttolxlwp(curthread)->br_ppid != 0);
	lxpd->l_tracer_pid = lwpd->br_ppid;
	lxpd->l_tracer_proc = pp;
	p->p_proc_flag |= P_PR_TRACE;
	p->p_proc_flag |= P_PR_PTRACE;
	p->p_proc_flag |= P_PR_LXPTRACE;
	p->p_proc_flag &= ~P_PR_FORK;

	lwpd->br_ptrace = 1;

	prfillset(&signals);
	prdelset(&signals, SIGKILL);
	prassignset(&p->p_sigmask, &signals);

	premptyset(&flts);
	prassignset(&p->p_fltmask, &flts);
	mutex_exit(&p->p_lock);
	
	mutex_enter(&pp->p_lock);
	pp->p_flag |= SJCTL;
	mutex_exit(&pp->p_lock);

	return (0);
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
	sigset_t signals;
	fltset_t flts;

	mutex_enter(&pidlock);
	cp = prfind(s_pid);
	if (cp == NULL) {
		mutex_exit(&pidlock);
		return (set_errno(ESRCH));
	}
	if (cp == pp) {
		mutex_exit(&pidlock);
		return (set_errno(EPERM));
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
		lxpd->l_tracer_proc = pp;
	} else {
	/* Acquiring something not our child requires more bookkeeping. */
		lxpd->l_tracer_pid = lxlwpd->br_pid;
		lxpd->l_tracer_proc = pp;
		/* Add to our trace list at the beginning if it exists, otherwise make the list. */
		if (lxlwpd->br_trace_list != NULL) {
			proc_t *head = lxlwpd->br_trace_list;
			lx_proc_data_t *lxhead;
		       
			mutex_enter(&head->p_lock);
			lxhead = ptolxproc(head);
			ASSERT(lxhead->l_trace_prev == NULL);
			lxhead->l_trace_prev = cp;
			lxpd->l_trace_next = head;
			lxlwpd->br_trace_list = cp;
			mutex_exit(&head->p_lock);
		} else {
			lxlwpd->br_trace_list = cp;
		}
	}
	ttolxlwp(t)->br_ptrace = 1;

	ASSERT(ttolxlwp(curthread)->br_pid != 0);
	cp->p_proc_flag |= P_PR_TRACE;
	cp->p_proc_flag |= P_PR_PTRACE;
	cp->p_proc_flag |= P_PR_LXPTRACE;
	cp->p_proc_flag &= ~P_PR_FORK;

	prfillset(&signals);
	prdelset(&signals, SIGKILL);
	prassignset(&cp->p_sigmask, &signals);

	premptyset(&flts);
	prassignset(&cp->p_fltmask, &flts);

	pp->p_flag |= SJCTL;

	
end:
	mutex_exit(&pp->p_lock);
	mutex_exit(&cp->p_lock);
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

	if ((err = acquire_and_validate_proc(s_pid, &cp)))
		return (set_errno(err));

	err = uread(cp, &k_data, sizeof (k_data), addr);
	if (err)
		return (set_errno(err));
	err = copyout(&k_data, data, sizeof (k_data));
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
	
	if ((err = acquire_and_validate_proc(s_pid, &cp)))
		return (set_errno(err));

	if (cp == NULL)
		return (set_errno(ESRCH));

	err = copyin(data, &k_data, sizeof (k_data));
	if(err)
		return (set_errno(EFAULT));
	err = uwrite(cp, &k_data, sizeof (k_data), addr);
	if (err)
		return (set_errno(err));
	
	return (0);
}
static int
get_proc_prnode(proc_t *p, prnode_t **outp)
{
	
	mutex_enter(&p->p_lock);
	if (p->p_trace != NULL) {
		*outp = VTOP(p->p_trace);
		mutex_exit(&p->p_lock);
	} else {
		vnode_t *procroot, *procdir;
		int err, i;
		pid_t pid = p->p_pid;
		char pidbuf[11]; /* assumes no more than 10 digits of process ids */

		mutex_exit(&p->p_lock);
		/* XXX: use BCD conversion algorithm to make this faster */
		pidbuf[10] = '\0';
		for (i = 9; i >= 0; --i) {
			pidbuf[i] = (pid % 10) + '0';
			pid /= 10;
		}

		if ((err = vn_openat("/proc", UIO_SYSSPACE, FREAD, 0,
		    &procroot, 0, 0, NULL, -1)) != 0) {
			return (err);
		}
		procdir = pr_lookup_procdir(procroot, pidbuf);
		if (procdir == NULL)
			return (EPERM);
		*outp = VTOP(procdir);
	}

	return (0);
}
static long
ptrace_cont(pid_t pid, pid_t s_pid, id_t s_tid, int data, boolean_t step)
{
	proc_t *p;
	kthread_t *t;
	klwp_t *lwp;
	int sig = ltos_signo[data];
	int err;
	prnode_t *pnp;

	if ((err = acquire_and_validate_proc(pid, &p)) != 0)
		return (set_errno(err));
	if ((err = acquire_and_validate_lwp(p, s_tid, &t)) != 0)
		return (set_errno(err));

	if (sig < 0 || sig >= LX_NSIG)
		return (set_errno(EINVAL));

	lwp = ttolwp(t);
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
		lwp->lwp_cursig = 0;
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

	if ((err = get_proc_prnode(p, &pnp)) != 0)
		return (set_errno(err));

	mutex_enter(&p->p_lock);
	if ((err = pr_setrun(pnp, (step == B_TRUE) ? PRSTEP : 0)) != 0) {
		mutex_exit(&p->p_lock);
		return (set_errno(err));
	}
	mutex_exit(&p->p_lock);

	return (0);
}

static long
ptrace_setoptions(pid_t s_pid, int opts)
{
	proc_t *p;
	lx_proc_data_t *lxpd;
	int err;
	
	if ((err = acquire_and_validate_proc(s_pid, &p)) != 0)
		return (set_errno(err));

	lxpd = ptolxproc(p);	
	lxpd->l_ptrace_opts = opts;
	return (0);
}

/*
 * gets the registers of thread t and copies them to a kernel memory address (loc)
 */
static long
lx_getregs(kthread_t *t, void *loc)
{

	lx_lwp_data_t *lwpd;
	lx_user_regs_t lxk_regs;

	lwpd = ttolxlwp(t);
	if (t->t_state == TS_STOPPED) {
		prgregset_t gk_regs;

		prgetprregs(ttolwp(t), gk_regs);

		/* 
		 * we set this field in lx_emulate, so that we get the correct
		 * values whether the lwp is in lx brand emulation code or just
		 * running normally.
		 */
		if (lwpd->br_regs == NULL) {
			lxk_regs.lxur_ebx = gk_regs[EBX];
			lxk_regs.lxur_ecx = gk_regs[ECX];
			lxk_regs.lxur_edx = gk_regs[EDX];
			lxk_regs.lxur_esi = gk_regs[ESI];
			lxk_regs.lxur_edi = gk_regs[EDI];
			lxk_regs.lxur_ebp = gk_regs[EBP];
			lxk_regs.lxur_eax = gk_regs[EAX];
			lxk_regs.lxur_xds = gk_regs[DS];
			lxk_regs.lxur_xes = gk_regs[ES];
			lxk_regs.lxur_xfs = gk_regs[FS];
			lxk_regs.lxur_xgs = gk_regs[GS];
			lxk_regs.lxur_orig_eax = 0;
			lxk_regs.lxur_eip = gk_regs[EIP];
			lxk_regs.lxur_xcs = gk_regs[CS];
			lxk_regs.lxur_eflags = gk_regs[EFL];
			lxk_regs.lxur_esp = gk_regs[UESP];
			lxk_regs.lxur_xss = gk_regs[SS];

			/*
			 * If the target process has just returned from exec, it's not
			 * going to be sitting in the emulation function. In that case
			 * we need to manually fake up the values for %eax and orig_eax
			 * to indicate a successful return and that the traced process
			 * had called execve (respectively).
			 */
			if (t->t_whystop == PR_SYSEXIT &&
					t->t_whatstop == SYS_execve) {
				lxk_regs.lxur_eax = 0;
				lxk_regs.lxur_orig_eax = LX_SYS_execve;
			}
		} else {
			lx_regs_t lx_emulate_regs;

			if (copyin(lwpd->br_regs, &lx_emulate_regs, sizeof (lx_regs_t)) < 0)
				return (set_errno(EFAULT)); /* this shouldn't happen */
			
			lxk_regs.lxur_ebx = lx_emulate_regs.lxr_ebx;
			lxk_regs.lxur_ecx = lx_emulate_regs.lxr_ecx;
			lxk_regs.lxur_edx = lx_emulate_regs.lxr_edx;
			lxk_regs.lxur_esi = lx_emulate_regs.lxr_esi;
			lxk_regs.lxur_edi = lx_emulate_regs.lxr_edi;
			lxk_regs.lxur_ebp = lx_emulate_regs.lxr_ebp;
			lxk_regs.lxur_eax = lx_emulate_regs.lxr_eax;
			lxk_regs.lxur_xds = gk_regs[DS];
			lxk_regs.lxur_xes = gk_regs[ES];
			lxk_regs.lxur_xfs = gk_regs[FS];
			lxk_regs.lxur_xgs = lx_emulate_regs.lxr_gs;
			lxk_regs.lxur_orig_eax = lx_emulate_regs.lxr_orig_eax;
			lxk_regs.lxur_eip = lx_emulate_regs.lxr_eip;
			lxk_regs.lxur_xcs = gk_regs[CS];
			lxk_regs.lxur_eflags = gk_regs[EFL];
			lxk_regs.lxur_esp = lx_emulate_regs.lxr_esp;
			lxk_regs.lxur_xss = gk_regs[SS];
		}
		bcopy(&lxk_regs, loc, sizeof (lx_user_regs_t));
	} else {
		return (EPERM);
	}

	return (0);

}

static long
lx_setregs(kthread_t *t, void *loc)
{
	lx_lwp_data_t *lwpd = ttolxlwp(t);
	lx_user_regs_t *lxk_regs = (lx_user_regs_t *)loc;

	if (t->t_state == TS_STOPPED) {
		prgregset_t gk_regs;
		
		prgetprregs(ttolwp(t), gk_regs);
		if (lwpd->br_regs == NULL) {
			gk_regs[EBX] = lxk_regs->lxur_ebx;
			gk_regs[ECX] = lxk_regs->lxur_ecx;
			gk_regs[EDX] = lxk_regs->lxur_edx;
			gk_regs[ESI] = lxk_regs->lxur_esi;
			gk_regs[EDI] = lxk_regs->lxur_edi;
			gk_regs[EBP] = lxk_regs->lxur_ebp;
			gk_regs[EAX] = lxk_regs->lxur_eax;
			gk_regs[DS] = lxk_regs->lxur_xds;
			gk_regs[ES] = lxk_regs->lxur_xes;
			gk_regs[FS] = lxk_regs->lxur_xfs;
			gk_regs[GS] = lxk_regs->lxur_xgs;
			gk_regs[EIP] = lxk_regs->lxur_eip;
			gk_regs[CS] = lxk_regs->lxur_xcs;
			gk_regs[EFL] = lxk_regs->lxur_eflags;
			gk_regs[UESP] = lxk_regs->lxur_esp;
			gk_regs[SS] = lxk_regs->lxur_xss;
		} else {
			lx_regs_t lx_emulate_regs;

			lx_emulate_regs.lxr_ebx = lxk_regs->lxur_ebx;
			lx_emulate_regs.lxr_ecx = lxk_regs->lxur_ecx;
			lx_emulate_regs.lxr_edx = lxk_regs->lxur_edx;
			lx_emulate_regs.lxr_esi = lxk_regs->lxur_esi;
			lx_emulate_regs.lxr_edi = lxk_regs->lxur_edi;
			lx_emulate_regs.lxr_ebp = lxk_regs->lxur_ebp;
			lx_emulate_regs.lxr_eax = lxk_regs->lxur_eax;
			gk_regs[DS] = lxk_regs->lxur_xds;
			gk_regs[ES] = lxk_regs->lxur_xes;
			gk_regs[FS] = lxk_regs->lxur_xfs;
			lx_emulate_regs.lxr_gs = lxk_regs->lxur_xgs;
			lx_emulate_regs.lxr_orig_eax = lxk_regs->lxur_orig_eax;
			lx_emulate_regs.lxr_eip = lxk_regs->lxur_eip;
			gk_regs[CS] = lxk_regs->lxur_xcs;
			gk_regs[EFL] = lxk_regs->lxur_eflags;
			lx_emulate_regs.lxr_esp = lxk_regs->lxur_esp;
			gk_regs[SS] = lxk_regs->lxur_xss;

			if (copyout(&lx_emulate_regs, lwpd->br_regs, sizeof (lx_regs_t)) < 0)
				return (EFAULT); /* this shouldn't happen */
	
		}
		prsetprregs(ttolwp(t), gk_regs, 0);
	}
	else {
		return (EPERM);
	}
	return (0);
}

long
ptrace_getregs(pid_t s_pid, pid_t s_tid, void *data)
{
	lx_user_regs_t lxk_regs;
	proc_t *p;
	kthread_t *t;
	int err;

	if ((err = acquire_and_validate_proc(s_pid, &p)) != 0)
		return (set_errno(err));
	if ((err = acquire_and_validate_lwp(p, s_tid, &t)) != 0)
		return (set_errno(err));
	
	if ((err = lx_getregs(t, &lxk_regs)) != 0)
		return (set_errno(err));
	if (copyout(&lxk_regs, data, sizeof (lx_user_regs_t)) < 0)
			return (set_errno(EPERM));
	return (0);
}

long
ptrace_setregs(pid_t s_pid, pid_t s_tid, void *data)
{
	lx_user_regs_t lxk_regs;
	proc_t *p;
	kthread_t *t;
	int err;

	if ((err = acquire_and_validate_proc(s_pid, &p)) != 0)
		return (set_errno(err));
	if ((err = acquire_and_validate_lwp(p, s_tid, &t)) != 0)
		return (set_errno(err));
	
	if (copyin(data, &lxk_regs, sizeof (lx_user_regs_t)) < 0)
		return (set_errno(EFAULT));
	if ((err = lx_setregs(t, &lxk_regs)) != 0)
		return (set_errno(err));
	return (0);
}

#define OFFSETOF(struct_name, member) \
	((size_t)(&((struct_name *)NULL)->member))

#define	LX_USER_BOUND(m)	\
(OFFSETOF(lx_user_t, m) + sizeof (((lx_user_t *)NULL)->m))

/*
 * peek into the user structure for linux. Right now only debug registers and
 * nromal registers are supported locations to peek.
 */
long
ptrace_peek_user(pid_t s_pid, id_t s_tid, int off, int *dst)
{
	proc_t *p;
	kthread_t *t;
	lx_lwp_data_t *lwpd;
	int err, data;

	if ((err = acquire_and_validate_proc(s_pid, &p)) != 0)
		return (set_errno(err));
	if ((err = acquire_and_validate_lwp(p, s_tid, &t)) != 0)
		return (set_errno(err));
	
	lwpd = ttolxlwp(t);

	/*
	 * The offset specified by the user is an offset into the Linux
	 * user structure (seriously). Rather than constructing a full
	 * user structure, we figure out which part of the user structure
	 * the offset is in, and fill in just that component.
	 */
	if (off < LX_USER_BOUND(lxu_regs)) {
		lx_user_regs_t regs;

		if ((err = lx_getregs(t, &regs)) != 0)
			return (set_errno(err));

		data = *(int *)((uintptr_t)&regs + off -
		    OFFSETOF(lx_user_t, lxu_regs));

	} else if (off < LX_USER_BOUND(lxu_fpvalid)) {
		return (set_errno(ENOTSUP));
	} else if (off < LX_USER_BOUND(lxu_i387)) {
		return (set_errno(ENOTSUP));
	} else if (off < LX_USER_BOUND(lxu_tsize)) {
		return (set_errno(ENOTSUP));
	} else if (off < LX_USER_BOUND(lxu_dsize)) {
		return (set_errno(ENOTSUP));
	} else if (off < LX_USER_BOUND(lxu_ssize)) {
		return (set_errno(ENOTSUP));
	} else if (off < LX_USER_BOUND(lxu_start_code)) {
		return (set_errno(ENOTSUP));
	} else if (off < LX_USER_BOUND(lxu_start_stack)) {
		return (set_errno(ENOTSUP));
	} else if (off < LX_USER_BOUND(lxu_signal)) {
		return (set_errno(ENOTSUP));
	} else if (off < LX_USER_BOUND(lxu_reserved)) {
		return (set_errno(ENOTSUP));
	} else if (off + 4 < LX_USER_BOUND(lxu_ar0)) {
		return (set_errno(ENOTSUP));
	} else if (off + 8 < LX_USER_BOUND(lxu_fpstate)) {
		return (set_errno(ENOTSUP));
	} else if (off + 8 < LX_USER_BOUND(lxu_magic)) {
		return (set_errno(ENOTSUP));
	} else if (off + 8 < LX_USER_BOUND(lxu_comm)) {
		return (set_errno(ENOTSUP));
	} else if (off + 8 < LX_USER_BOUND(lxu_debugreg)) {
		/*
		 * Solaris does not allow a process to manipulate its own or
		 * some other process's debug registers.  Linux ptrace(2)
		 * allows this and gdb manipulates them for its watchpoint
		 * implementation.
		 *
		 * We keep a set of pseudo debug registers in the thread
		 * specific data, and then when there are writes to register 7
		 * make state changes appropriately.
		 *
		 * To understand how the debug registers work on x86 machines,
		 * see section 17 of volume 3B of the Intel Software Developer Manual
		 */
		int dreg = (off - OFFSETOF(lx_user_t, lxu_debugreg)) / sizeof (int);

		if (dreg == 4)		/* aliased by the architecture */
			dreg = 6;
		else if (dreg == 5)	/* aliased by the architecture */
			dreg = 7;
		data = lwpd->br_debug_regs[dreg];
	} else {
		return (set_errno(ENOTSUP));
	}

	if ((err = copyout(&data, dst, sizeof (data))) != 0)
		return (set_errno(err));

	return (0);

}



int
setup_watchpoints(proc_t *p)
{
	prnode_t *pnp;
	int err, unlocked = 1;
	int i = 0;
	struct watched_area *pwp;
	lx_lwp_data_t *lwpd = ttolxlwp(curthread);
	int dr7 = lwpd->br_debug_regs[7];
	int lrw;

	if ((err = get_proc_prnode(p, &pnp)) != 0)
		return (err);

	if ((err = prlock(pnp, ZNO)) != 0)
		return (err);
	unlocked = 1;

	/* 
	 * We first stop all threads in the process, theoretically this should
	 * happen after validating that at least some watchpoint should happen 
	 */
	pauselwps(p);
	while (pr_allstopped(p, 0) > 0) {
		/*
		 * This cv/mutex pair is persistent even
		 * if the process disappears after we
		 * unmark it and drop p->p_lock.
		 */
		kcondvar_t *cv = &pr_pid_cv[p->p_slot];
		kmutex_t *mp = &p->p_lock;

		prunmark(p);
		(void) cv_wait(cv, mp);
		mutex_exit(mp);
		if ((err = prlock(pnp, ZNO)) != 0) {
			/*
			 * Unpause the process if it exists.
			 */
			p = pr_p_lock(pnp);
			mutex_exit(&pr_pidlock);
			if (p != NULL) {
				unpauselwps(p);
				prunlock(pnp);
			}
			unlocked = 1;
			return (err);
		}
	}

	/* now clear all set watchpoints */
	while (avl_numnodes(&p->p_warea) > 0 && err == 0) {
		pwp = avl_first(&p->p_warea);
		mutex_exit(&p->p_lock);
		err = clear_watched_area(p, pwp);
		mutex_enter(&p->p_lock);
	}

	if (err != 0) {
		unpauselwps(p);
		prunlock(pnp);
		return (err);
	}
	/* now we can actually set the watchpoints we want. */
	for (i = 0; i < 4 && err == 0; ++i) {
		struct watched_area *new_area;
		int size = 0;
		int flags = 0;

		if ((dr7 & (1 << (2 * i))) == 0) /* this bit set if enabled */
			continue;

		mutex_exit(&p->p_lock);
		new_area = kmem_alloc(sizeof (struct watched_area), KM_SLEEP);
		/* 
		 * Parameters for each watch point are stored in groups of four
		 * bits starting at bit 16 for watchpoint 0. 
		 */
		lrw = (dr7 >> (16 + (4 * i))) & 0xf;
		switch  (lrw << 2) {
			case 0: size = 1; break;
			case 1: size = 2; break;
			case 2: size = 8; break;
			case 3: size = 4; break;
		}
		switch (lrw & 0x3) {
			case 0: flags = WA_EXEC; break;
			case 1: flags = WA_WRITE; break;
			case 2: continue;
			case 3: flags = WA_READ | WA_WRITE;
		}
		flags |= WA_TRAPAFTER;

		if ((~(uintptr_t)0) - size < lwpd->br_debug_regs[i]) {
			err = EINVAL;
			continue;
		}
		new_area->wa_vaddr = (void *)lwpd->br_debug_regs[i];
		new_area->wa_eaddr = (void *)lwpd->br_debug_regs[i] + size;
		new_area->wa_flags = flags;
		
		err = set_watched_area(p, new_area);
		mutex_enter(&p->p_lock);
	}

	unpauselwps(p);
	prunlock(pnp);
	return (err);
}

/*
 * change the user structure for linux. Right now only debug registers and
 * nromal registers are supported locations to poke.
 */
long
ptrace_poke_user(pid_t s_pid, id_t s_tid, int off, int *src)
{
	proc_t *p;
	kthread_t *t;
	lx_lwp_data_t *lwpd;
	int err, data;

	if ((err = acquire_and_validate_proc(s_pid, &p)) != 0)
		return (set_errno(err));
	if ((err = acquire_and_validate_lwp(p, s_tid, &t)) != 0)
		return (set_errno(err));
	if ((err = copyin(src, &data, sizeof (data))) != 0)
		return (set_errno(err));

	lwpd = ttolxlwp(t);
	/*
	 * The offset specified by the user is an offset into the Linux
	 * user structure (seriously). Rather than constructing a full
	 * user structure, we figure out which part of the user structure
	 * the offset is in, and fill in just that component.
	 */
	if (off < LX_USER_BOUND(lxu_regs)) {
		lx_user_regs_t regs;
		int loc;

		if ((err = lx_getregs(t, &regs)) != 0)
			return (set_errno(err));

		loc = off - OFFSETOF(lx_user_t, lxu_regs);
		((char *)(&regs))[loc] = data;
		if ((err = lx_setregs(t, &regs)) != 0)
			return (set_errno(err));
	} else if (off < LX_USER_BOUND(lxu_fpvalid)) {
		return (set_errno(ENOTSUP));
	} else if (off < LX_USER_BOUND(lxu_i387)) {
		return (set_errno(ENOTSUP));
	} else if (off < LX_USER_BOUND(lxu_tsize)) {
		return (set_errno(ENOTSUP));
	} else if (off < LX_USER_BOUND(lxu_dsize)) {
		return (set_errno(ENOTSUP));
	} else if (off < LX_USER_BOUND(lxu_ssize)) {
		return (set_errno(ENOTSUP));
	} else if (off < LX_USER_BOUND(lxu_start_code)) {
		return (set_errno(ENOTSUP));
	} else if (off < LX_USER_BOUND(lxu_start_stack)) {
		return (set_errno(ENOTSUP));
	} else if (off < LX_USER_BOUND(lxu_signal)) {
		return (set_errno(ENOTSUP));
	} else if (off < LX_USER_BOUND(lxu_reserved)) {
		return (set_errno(ENOTSUP));
	} else if (off < LX_USER_BOUND(lxu_ar0)) {
		return (set_errno(ENOTSUP));
	} else if (off < LX_USER_BOUND(lxu_fpstate)) {
		return (set_errno(ENOTSUP));
	} else if (off < LX_USER_BOUND(lxu_magic)) {
		return (set_errno(ENOTSUP));
	} else if (off < LX_USER_BOUND(lxu_comm)) {
		return (set_errno(ENOTSUP));
	} else if (off < LX_USER_BOUND(lxu_debugreg)) {
		int dreg = (off - OFFSETOF(lx_user_t, lxu_debugreg)) / sizeof (int);
		if (dreg == 4)		/* aliased by the architecture */
			dreg = 6;
		else if (dreg == 5)	/* aliased by the architecture */
			dreg = 7;
		lwpd->br_debug_regs[dreg] = data;
		if (dreg == 7)
			err = setup_watchpoints(p);
		if (err != 0)
			return (set_errno(err));

	} else {
		return (set_errno(ENOTSUP));
	}

	return (0);

}

long
ptrace_kill(pid_t s_pid, id_t s_tid)
{
	proc_t *p;
	kthread_t *t;
	int err;

	if ((err = acquire_and_validate_proc(s_pid, &p)) != 0)
		return (set_errno(err));
	if ((err = acquire_and_validate_lwp(p, s_tid, &t)) != 0)
		return (set_errno(err));

	psignal(p, SIGKILL);

	return (0);

}

long
lx_ptrace(long request, long pid, unsigned long addr, unsigned long data)
{
	pid_t l_pid = (pid_t)pid;
	pid_t s_pid;
	id_t s_tid;

	if (request != LX_PTRACE_TRACEME)
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
		return (ptrace_poke(s_pid, addr, (int *)data));

	case LX_PTRACE_CONT:
		return (ptrace_cont(pid, s_pid, s_tid, (int)data, B_FALSE));

	case LX_PTRACE_ATTACH:
		return (ptrace_attach(pid, s_pid, s_tid));

	case LX_PTRACE_SETOPTIONS:
		return (ptrace_setoptions(s_pid, (int)data));

	case LX_PTRACE_GETREGS:
		return (ptrace_getregs(s_pid, s_tid, (void *)data));

	case LX_PTRACE_SETREGS:
		return (ptrace_setregs(s_pid, s_tid, (void *)data));

	case LX_PTRACE_SINGLESTEP:
		return (ptrace_cont(pid, s_pid, s_tid, (int)data, B_TRUE));

	case LX_PTRACE_PEEKUSER:
		return (ptrace_peek_user(s_pid, s_tid, addr, (int *)data));

	case LX_PTRACE_POKEUSER:
		return (ptrace_poke_user(s_pid, s_tid, addr, (int *)data));

	case LX_PTRACE_KILL:
		return (ptrace_kill(s_pid, s_tid));

/*
   
	case LX_PTRACE_DETACH:
		return (ptrace_detach(pid, s_pid, s_tid, (int)data));

	case LX_PTRACE_GETFPREGS:
		return (ptrace_getfpregs(s_pid, s_tid, data));

	case LX_PTRACE_SETFPREGS:
		return (ptrace_setfpregs(s_pid, s_tid, data));

	case LX_PTRACE_GETFPXREGS:
		return (ptrace_getfpxregs(s_pid, s_tid, data));

	case LX_PTRACE_SETFPXREGS:
		return (ptrace_setfpxregs(s_pid, s_tid, data));

	case LX_PTRACE_SYSCALL:
		return (ptrace_syscall(pid, s_pid, s_tid, (int)data));
*/
	default:
		return (-EINVAL);
	}
}

static boolean_t
ptrace_event_to_marker(int event, uint_t *ret)
{
	switch (event) {
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
	lx_proc_data_t *lxpd = ptolxproc(p);
	sigqueue_t *sqp;
	proc_t *pp = lxpd->l_tracer_proc;

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
		sigcld_target(p, pp, sqp);
		mutex_exit(&pidlock);

		/* this is what we actually want */
		p->p_wcode = CLD_TRAPPED;
	}
	return (0);
}

/*
 * This is where all of forking ptrace flags gets handled. Ptrace flags are
 * only forked when the correct event is set by the parent. In the case where
 * it is set, then the child inherits all of the ptrace information from the
 * parent, and stops with SIGSTOP.
 */
int
lx_ptrace_child(int event)
{
	proc_t *p = curproc;
	lx_proc_data_t *lxpd = ptolxproc(p);
	sigqueue_t *sqp;
	proc_t *pp;
	pid_t s_pid;
	id_t s_tid;
	int err;
	kthread_t *t;

	if ((err = lx_lwp_ppid(curthread->t_lwp, &s_pid, &s_tid)) < 0)
		return (set_errno(EINVAL));

	mutex_enter(&pidlock);	
	pp = prfind(s_pid);	
	mutex_exit(&pidlock);
	if (pp == NULL)
		return (set_errno(EINVAL));

	mutex_enter(&pp->p_lock);
	t = idtot(pp, s_tid);
	if (t == NULL) {
		mutex_exit(&pp->p_lock);
		return (set_errno(EINVAL));
	}


	if (event & ptolxproc(pp)->l_ptrace_opts) {
		lx_proc_data_t *lxppd = ptolxproc(pp);
		lx_lwp_data_t *lwppd = ttolxlwp(t);
		lx_lwp_data_t *lwpd = ttolxlwp(curthread);

		/* 
		 * copy over ptrace information, essentially attaching the
		 * current proc to the tracer of its parent. 
		 */
		mutex_enter(&p->p_lock);
		lxpd->l_ptrace_opts = lxppd->l_ptrace_opts;
		lxpd->l_tracer_pid = lxppd->l_tracer_pid;
		lxpd->l_tracer_proc = lxppd->l_tracer_proc;
		lwpd->br_ptrace = lwppd->br_ptrace;
		bcopy(lwppd->br_debug_regs, lwpd->br_debug_regs, sizeof(uintptr_t) * 8);		
		/* 
		 * add ourselves to the list of extra children to wait on if
		 * not a direct descendant of tracer 
		 */
		if (pp != lxpd->l_tracer_proc) {
			/* Add to our trace list at the beginning if it exists, otherwise make the list. */
			if (lwppd->br_trace_list != NULL) {
				proc_t *head = lwppd->br_trace_list;
				lx_proc_data_t *lxhead;

				mutex_enter(&head->p_lock);
				lxhead = ptolxproc(head);
				ASSERT(lxhead->l_trace_prev == NULL);
				lxhead->l_trace_prev = p;
				lxpd->l_trace_next = head;
				lwppd->br_trace_list = p;
				mutex_exit(&head->p_lock);
			} else {
				lwppd->br_trace_list = p;
			}
		}

		/*
		 * children stop and send a sigchld back to their tracer, which
		 * has been set by the point this is called.
		 */
		mutex_exit(&p->p_lock);
		mutex_exit(&pp->p_lock);
		psignal(p, SIGSTOP);

		sqp = kmem_zalloc(sizeof (sigqueue_t), KM_SLEEP);
		mutex_enter(&pidlock);
		p->p_wdata = SIGTRAP;
		/* CLD_STOPPED is used here to get around the assert in sigcld */
		p->p_wcode = CLD_STOPPED;
		sigcld_target(p, pp, sqp);
		mutex_exit(&pidlock);

		/* this is what we actually want */
		p->p_wcode = CLD_TRAPPED;

	}
	return (0);
}
