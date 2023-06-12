// /* This file is derived from source code for the Nachos
//    instructional operating system.  The Nachos copyright notice
//    is reproduced in full below. */

// /* Copyright (c) 1992-1996 The Regents of the University of California.
//    All rights reserved.

//    Permission to use, copy, modify, and distribute this software
//    and its documentation for any purpose, without fee, and
//    without written agreement is hereby granted, provided that the
//    above copyright notice and the following two paragraphs appear
//    in all copies of this software.

//    IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
//    ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
//    CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
//    AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
//    HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//    THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
//    WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
//    PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
//    BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
//    PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
//    MODIFICATIONS.
//    */

// #include "threads/synch.h"
// #include <stdio.h>
// #include <string.h>
// #include "threads/interrupt.h"
// #include "threads/thread.h"

// /* Initializes semaphore SEMA to VALUE.  A semaphore is a
//    nonnegative integer along with two atomic operators for
//    manipulating it:

//    - down or "P": wait for the value to become positive, then
//    decrement it.

//    - up or "V": increment the value (and wake up one waiting
//    thread, if any). */
// void
// sema_init (struct semaphore *sema, unsigned value) {
// 	ASSERT (sema != NULL);

// 	sema->value = value;
// 	list_init (&sema->waiters);
// }

// /* Down or "P" operation on a semaphore.  Waits for SEMA's value
//    to become positive and then atomically decrements it.

//    This function may sleep, so it must not be called within an
//    interrupt handler.  This function may be called with
//    interrupts disabled, but if it sleeps then the next scheduled
//    thread will probably turn interrupts back on. This is
//    sema_down function. */
// void
// sema_down (struct semaphore *sema) {
// 	enum intr_level old_level;

// 	ASSERT (sema != NULL);
// 	ASSERT (!intr_context ());
// 	old_level = intr_disable ();

// 	while (sema->value == 0) {
// 		/*이미 공유자원이 lock 인 상태일 경우, lock의 waiters 에 현재 thread를 추가한다. 단 우선순위에 정렬을 사용해서. */
// 		list_insert_ordered(&sema->waiters, &thread_current()->elem, priority_sort, NULL);
// 		thread_block ();
// 	}
// 	sema->value--;
// 	intr_set_level (old_level);
// }

// /* Down or "P" operation on a semaphore, but only if the
//    semaphore is not already 0.  Returns true if the semaphore is
//    decremented, false otherwise.

//    This function may be called from an interrupt handler. */
// bool
// sema_try_down (struct semaphore *sema) {
// 	enum intr_level old_level;
// 	bool success;

// 	ASSERT (sema != NULL);

// 	old_level = intr_disable ();
// 	if (sema->value > 0)
// 	{
// 		sema->value--;
// 		success = true;
// 	}
// 	else
// 		success = false;
// 	intr_set_level (old_level);

// 	return success;
// }

// /* Up or "V" operation on a semaphore.  Increments SEMA's value
//    and wakes up one thread of those waiting for SEMA, if any.

//    This function may be called from an interrupt handler. */
// void
// sema_up (struct semaphore *sema) { 
// 	enum intr_level old_level;

// 	ASSERT (sema != NULL);

// 	old_level = intr_disable ();
// 	if (!list_empty(&sema->waiters)){
// 		/*waiter에 넣을때도 sort를 하지만, 만약 스레드 자체에 우선순위가 변했을 수도 있기에 정렬 한번 더*/
// 		list_sort(&sema->waiters, priority_sort, NULL);
// 		thread_unblock (list_entry (list_pop_front (&sema->waiters),
// 					struct thread, elem));
// 	}
// 	sema->value++;
// 	priority_preempt();
// 	intr_set_level (old_level);
// }

// static void sema_test_helper (void *sema_);

// /* Self-test for semaphores that makes control "ping-pong"
//    between a pair of threads.  Insert calls to printf() to see
//    what's going on. */
// void
// sema_self_test (void) {
// 	struct semaphore sema[2];
// 	int i;

// 	printf ("Testing semaphores...");
// 	sema_init (&sema[0], 0);
// 	sema_init (&sema[1], 0);
// 	thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
// 	for (i = 0; i < 10; i++)
// 	{
// 		sema_up (&sema[0]);
// 		sema_down (&sema[1]);
// 	}
// 	printf ("done.\n");
// }

// /* Thread function used by sema_self_test(). */
// static void
// sema_test_helper (void *sema_) {
// 	struct semaphore *sema = sema_;
// 	int i;

// 	for (i = 0; i < 10; i++)
// 	{
// 		sema_down (&sema[0]);
// 		sema_up (&sema[1]);
// 	}
// }

// /* Initializes LOCK.  A lock can be held by at most a single
//    thread at any given time.  Our locks are not "recursive", that
//    is, it is an error for the thread currently holding a lock to
//    try to acquire that lock.

//    A lock is a specialization of a semaphore with an initial
//    value of 1.  The difference between a lock and such a
//    semaphore is twofold.  First, a semaphore can have a value
//    greater than 1, but a lock can only be owned by a single
//    thread at a time.  Second, a semaphore does not have an owner,
//    meaning that one thread can "down" the semaphore and then
//    another one "up" it, but with a lock the same thread must both
//    acquire and release it.  When these restrictions prove
//    onerous, it's a good sign that a semaphore should be used,
//    instead of a lock. */
// void
// lock_init (struct lock *lock) {
// 	ASSERT (lock != NULL);

// 	lock->holder = NULL;
// 	sema_init (&lock->semaphore, 1);
// }

// /* Acquires LOCK, sleeping until it becomes available if
//    necessary. The lock must not already be held by the current
//    thread.

//    This function may sleep, so it must not be called within an
//    interrupt handler.  This function may be called with
//    interrupts disabled, but interrupts will be turned back on if
//    we need to sleep. */

// /* lock_acquire은 현재 돌고 있는 스레드가 인자값으로 넘겨준 lock을 점유하고 싶다고 호출한다.*/
// void
// lock_acquire (struct lock *lock) {
// 	ASSERT (lock != NULL);
// 	ASSERT (!intr_context ());
// 	ASSERT (!lock_held_by_current_thread (lock));
// 	/* 만약, lock의 holder가 NULL이 아니면, 누군가 점유하고 있다는 뜻이다.*/
// 	if(lock->holder != NULL){
// 		/* 그래서 현재 스레드는 해당 lock을 점유할 순 없다, 하지만 wait하고 있다고 wait_on_lock에 lock을 저장해놓는다.*/
// 		/* 이유는, 어떤 스레드가 lock을 해제할 때, 해당 lock 관련 스레드를 Donation_list에서 같이 삭제 해줘야함*/
// 		thread_current()->wait_on_lock = lock; 
// 		/*만약에 점유하지 못한 스래드들은 다~ Donations 리스트에 들어감.*/
// 		list_insert_ordered(&lock->holder->donations, &thread_current()->donation_elem, donation_sort, NULL);
// 		/* 그리고 도네이션 받아야 하면 받음 */
// 		donate_priority();
// 	}
// 	sema_down (&lock->semaphore);
// 	thread_current()->wait_on_lock = NULL;
// 	lock->holder = thread_current ();
// }

// /* Tries to acquires LOCK and returns true if successful or false
//    on failure.  The lock must not already be held by the current
//    thread.

//    This function will not sleep, so it may be called within an
//    interrupt handler. */
// bool
// lock_try_acquire (struct lock *lock) {
// 	bool success;

// 	ASSERT (lock != NULL);
// 	ASSERT (!lock_held_by_current_thread (lock));

// 	success = sema_try_down (&lock->semaphore);
// 	if (success)
// 		lock->holder = thread_current ();
// 	return success;
// }

// /* Releases LOCK, which must be owned by the current thread.
//    This is lock_release function.

//    An interrupt handler cannot acquire a lock, so it does not
//    make sense to try to release a lock within an interrupt
//    handler. */
// void
// lock_release (struct lock *lock) {
// 	ASSERT (lock != NULL);
// 	ASSERT (lock_held_by_current_thread (lock));
// 	remove_with_lock(lock);
// 	refresh_priority();
// 	lock->holder = NULL;
// 	sema_up (&lock->semaphore);
// }

// void 
// refresh_priority(void){
// 	struct thread *curr = thread_current();
// 	/*현재 도네이션이 비어있는지 아닌지 체크*/
// 	struct list *donation_list = &(curr->donations);
// 	/*비어있지 않으면, 도네이션 리스트의 첫번째 값이 현재 priority보다 높으면 변경*/
// 	if (list_empty(donation_list)){
// 		/* 우선 다시 우선순위 원래대로 복원해주고*/
// 		curr->priority = curr->original_priority;
// 	} else {
// 		list_sort(donation_list, donation_sort, NULL);
// 		struct thread *donation_first = list_entry(list_front(donation_list), struct thread, donation_elem);
// 		curr->priority = donation_first->priority;
// 	}
// }

// /* Returns true if the current thread holds LOCK, false
//    otherwise.  (Note that testing whether some other thread holds
//    a lock would be racy.) */
// bool
// lock_held_by_current_thread (const struct lock *lock) {
// 	ASSERT (lock != NULL);

// 	return lock->holder == thread_current ();
// }

// /* One semaphore in a list. */
// struct semaphore_elem {
// 	struct list_elem elem;              /* List element. */
// 	struct semaphore semaphore;         /* This semaphore. */
// };

// /* Initializes condition variable COND.  A condition variable
//    allows one piece of code to signal a condition and cooperating
//    code to receive the signal and act upon it. */
// void
// cond_init (struct condition *cond) {
// 	ASSERT (cond != NULL);

// 	list_init (&cond->waiters);
// }

// /* Atomically releases LOCK and waits for COND to be signaled by
//    some other piece of code.  After COND is signaled, LOCK is
//    reacquired before returning.  LOCK must be held before calling
//    this function.

//    The monitor implemented by this function is "Mesa" style, not
//    "Hoare" style, that is, sending and receiving a signal are not
//    an atomic operation.  Thus, typically the caller must recheck
//    the condition after the wait completes and, if necessary, wait
//    again.

//    A given condition variable is associated with only a single
//    lock, but one lock may be associated with any number of
//    condition variables.  That is, there is a one-to-many mapping
//    from locks to condition variables.

//    This function may sleep, so it must not be called within an
//    interrupt handler.  This function may be called with
//    interrupts disabled, but interrupts will be turned back on if
//    we need to sleep. */
// void
// cond_wait (struct condition *cond, struct lock *lock) {
//     struct semaphore_elem waiter;
    
// 	ASSERT (cond != NULL);
//     ASSERT (lock != NULL);
//     ASSERT (!intr_context ());
//     ASSERT (lock_held_by_current_thread (lock));
    
// 	sema_init (&waiter.semaphore, 0);
//     list_insert_ordered(&cond->waiters, &waiter.elem, cmp_sem_priority, NULL);
//     lock_release (lock);
//     sema_down (&waiter.semaphore);
//     lock_acquire (lock);
// }

// /* If any threads are waiting on COND (protected by LOCK), then
//    this function signals one of them to wake up from its wait.
//    LOCK must be held before calling this function.

//    An interrupt handler cannot acquire a lock, so it does not
//    make sense to try to signal a condition variable within an
//    interrupt handler. */
// void
// cond_signal (struct condition *cond, struct lock *lock UNUSED) {
//     ASSERT (cond != NULL);
//     ASSERT (lock != NULL);
//     ASSERT (!intr_context ());
//     ASSERT (lock_held_by_current_thread (lock));
//     if (!list_empty (&cond->waiters)) {
//         // 대기 중 우선순위 변경 가능성이 있어 재 정렬
//         list_sort(&cond->waiters, cmp_sem_priority, NULL);
//         // 여기 코드를 좀 분석
//         sema_up (&list_entry (list_pop_front (&cond->waiters),
//                     struct semaphore_elem, elem)->semaphore);
//     }
// }

// /* Wakes up all threads, if any, waiting on COND (protected by
//    LOCK).  LOCK must be held before calling this function.

//    An interrupt handler cannot acquire a lock, so it does not
//    make sense to try to signal a condition variable within an
//    interrupt handler. */
// void
// cond_broadcast (struct condition *cond, struct lock *lock) {
// 	ASSERT (cond != NULL);
// 	ASSERT (lock != NULL);

// 	while (!list_empty (&cond->waiters))
// 		cond_signal (cond, lock);
// }


// bool 
// cmp_sem_priority(const struct list_elem *a, const struct list_elem *b, void *aux) {
//  	struct semaphore_elem *sa = list_entry(a, struct semaphore_elem, elem);
//  	struct semaphore_elem *sb = list_entry(b, struct semaphore_elem, elem);

//  	struct list *la = &sa->semaphore.waiters;
//  	struct list *lb = &sb->semaphore.waiters;

//  	//list_begin() : list의 첫번째 반환
//  	struct thread *ta = list_entry(list_begin(la), struct thread, elem);
//  	struct thread *tb = list_entry(list_begin(lb), struct thread, elem);

//  	return ta->priority > tb->priority;
//  }


// void remove_with_lock(struct lock *lock){
// 	struct list_elem *li;
// 	struct thread *t;
// 	if (!list_empty(&lock->holder->donations)){
// 		li = list_front(&lock->holder->donations);
// 	}
// 	while (!list_empty(&lock->holder->donations)) {
// 		/*리스트로 해당 thread를 찾고*/
// 		if(li == list_tail(&lock->holder->donations)){
// 			break;
// 		}
// 		t = list_entry(li, struct thread, donation_elem);
// 		/*만약 도네이션에 있는 리스트의 wait_on_lock이 현재 지우려고하는 lock이면*/
// 		if(t->wait_on_lock == lock){
// 			/*해당 리스트를 도네이션 리스트에서 지워준다.*/
// 			list_remove(li);
// 		}
// 		li = list_next(li);
// 	}
// }


// bool
// wakeup_sort (const struct list_elem *a_, const struct list_elem *b_,
//             void *aux UNUSED) 
// {
//   const struct thread *a = list_entry (a_, struct thread, elem);
//   const struct thread *b = list_entry (b_, struct thread, elem);
  
//   return a->wakeup_tick < b->wakeup_tick;
// }

// bool
// priority_sort (const struct list_elem *a_, const struct list_elem *b_,
//             void *aux UNUSED) 
// {
//   const struct thread *a = list_entry (a_, struct thread, elem);
//   const struct thread *b = list_entry (b_, struct thread, elem);
  
//   return a->priority > b->priority;
// }

// bool
// donation_sort (const struct list_elem *a_, const struct list_elem *b_,
//             void *aux UNUSED) 
// {
//   const struct thread *a = list_entry (a_, struct thread, donation_elem);
//   const struct thread *b = list_entry (b_, struct thread, donation_elem);
  
//   return a->priority > b->priority;
// }


/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
   */

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
   decrement it.

   - up or "V": increment the value (and wake up one waiting
   thread, if any). */
void sema_init(struct semaphore *sema, unsigned value)
{
	ASSERT(sema != NULL);

	sema->value = value;
	list_init(&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. This is
   sema_down function. */
// 세마포어를 획득할 때까지 기다리고, 획득하면 세마포어의 값을 1 감소시키는 함수
void sema_down(struct semaphore *sema)
{
	enum intr_level old_level;

	ASSERT(sema != NULL);
	ASSERT(!intr_context());

	old_level = intr_disable();
	while (sema->value == 0) // 세마포어 값이 0인 경우, 세마포어 값이 양수가 될 때까지 대기
	{
		list_insert_ordered(&sema->waiters, &thread_current()->elem, cmp_thread_priority, NULL);
		thread_block(); // 스레드는 대기 상태에 들어감
	}
	sema->value--; // 세마포어 값이 양수가 되면, 세마포어 값을 1 감소
	intr_set_level(old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool sema_try_down(struct semaphore *sema)
{
	enum intr_level old_level;
	bool success;

	ASSERT(sema != NULL);

	old_level = intr_disable();
	if (sema->value > 0)
	{
		sema->value--;
		success = true;
	}
	else
		success = false;
	intr_set_level(old_level);

	return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
// 대기 중인 스레드 중 하나를 깨우고, 세마포어의 값을 1 증가시키는 함수
void sema_up(struct semaphore *sema)
{
	enum intr_level old_level;

	ASSERT(sema != NULL);

	old_level = intr_disable();
	if (!list_empty(&sema->waiters)) // 대기 중인 스레드를 깨움
	{
		// waiters에 들어있는 스레드가 donate를 받아 우선순위가 달라졌을 수 있기 때문에 재정렬
		list_sort(&sema->waiters, cmp_thread_priority, NULL);
		thread_unblock(list_entry(list_pop_front(&sema->waiters), struct thread, elem));
	}
	sema->value++;
	intr_set_level(old_level);
	preempt_priority(); // unblock이 호출되며 ready_list가 수정되었으므로 선점 여부 확인
}

static void sema_test_helper(void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void sema_self_test(void)
{
	struct semaphore sema[2];
	int i;

	printf("Testing semaphores...");
	sema_init(&sema[0], 0);
	sema_init(&sema[1], 0);
	thread_create("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
	for (i = 0; i < 10; i++)
	{
		sema_up(&sema[0]);
		sema_down(&sema[1]);
	}
	printf("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper(void *sema_)
{
	struct semaphore *sema = sema_;
	int i;

	for (i = 0; i < 10; i++)
	{
		sema_down(&sema[0]);
		sema_up(&sema[1]);
	}
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void lock_init(struct lock *lock)
{
	ASSERT(lock != NULL);

	lock->holder = NULL;
	sema_init(&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void lock_acquire(struct lock *lock)
{
	ASSERT(lock != NULL);
	ASSERT(!intr_context());
	ASSERT(!lock_held_by_current_thread(lock));

	struct thread *curr = thread_current();
	if (lock->holder != NULL) // 이미 점유중인 락이라면
	{
		curr->wait_on_lock = lock; // 현재 스레드의 wait_on_lock으로 지정
		// lock holder의 donors list에 현재 스레드 추가
		list_insert_ordered(&lock->holder->donations, &curr->donation_elem, cmp_donation_priority, NULL);
		donate_priority(); // 현재 스레드의 priority를 lock holder에게 상속해줌
	}

	sema_down(&lock->semaphore); // lock 점유

	curr->wait_on_lock = NULL; // lock을 점유했으니 wait_on_lock에서 제거

	lock->holder = thread_current();
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool lock_try_acquire(struct lock *lock)
{
	bool success;

	ASSERT(lock != NULL);
	ASSERT(!lock_held_by_current_thread(lock));

	success = sema_try_down(&lock->semaphore);
	if (success)
		lock->holder = thread_current();
	return success;
}

/* Releases LOCK, which must be owned by the current thread.
   This is lock_release function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void lock_release(struct lock *lock)
{
	ASSERT(lock != NULL);
	ASSERT(lock_held_by_current_thread(lock));

	remove_donor(lock);
	update_priority_for_donations();

	lock->holder = NULL;
	sema_up(&lock->semaphore);
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool lock_held_by_current_thread(const struct lock *lock)
{
	ASSERT(lock != NULL);

	return lock->holder == thread_current();
}

/* One semaphore in a list. */
struct semaphore_elem
{
	struct list_elem elem;		/* List element. */
	struct semaphore semaphore; /* This semaphore. */
};

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void cond_init(struct condition *cond)
{
	ASSERT(cond != NULL);

	list_init(&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
// 프로세스가 block 상태로 바뀌고, 조건 변수의 신호를 기다리는 함수
void cond_wait(struct condition *cond, struct lock *lock)
{
	struct semaphore_elem waiter;

	ASSERT(cond != NULL);
	ASSERT(lock != NULL);
	ASSERT(!intr_context());
	ASSERT(lock_held_by_current_thread(lock));

	sema_init(&waiter.semaphore, 0);
	list_insert_ordered(&cond->waiters, &waiter.elem, cmp_sema_priority, NULL);
	lock_release(lock);
	sema_down(&waiter.semaphore);
	lock_acquire(lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
// 조건 변수에서 가장 높은 우선순위를 가진 스레드에게 시그널을 보내는 함수
void cond_signal(struct condition *cond, struct lock *lock UNUSED)
{
	ASSERT(cond != NULL);
	ASSERT(lock != NULL);
	ASSERT(!intr_context());
	ASSERT(lock_held_by_current_thread(lock));

	if (!list_empty(&cond->waiters))
	{
		list_sort(&cond->waiters, cmp_sema_priority, NULL);
		sema_up(&list_entry(list_pop_front(&cond->waiters),
							struct semaphore_elem, elem)
					 ->semaphore);
	}
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
// 조건 변수에서 대기 상태에 있는 모든 스레드에게 시그널을 보내는 함수
void cond_broadcast(struct condition *cond, struct lock *lock)
{
	ASSERT(cond != NULL);
	ASSERT(lock != NULL);

	while (!list_empty(&cond->waiters))
		cond_signal(cond, lock);
}

// 두 sema 안의 'waiters list 안의 스레드 중 제일 높은 priority'를 비교해서 높으면 true를 반환하는 함수
bool cmp_sema_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED)
{
	struct semaphore_elem *sema_a = list_entry(a, struct semaphore_elem, elem);
	struct semaphore_elem *sema_b = list_entry(b, struct semaphore_elem, elem);

	struct list *waiters_a = &(sema_a->semaphore.waiters);
	struct list *waiters_b = &(sema_b->semaphore.waiters);

	struct thread *root_a = list_entry(list_begin(waiters_a), struct thread, elem);
	struct thread *root_b = list_entry(list_begin(waiters_b), struct thread, elem);

	return root_a->priority > root_b->priority;
}

// donation_elem의 priority를 기준으로 정렬하는 함수
bool cmp_donation_priority(const struct list_elem *a,
						   const struct list_elem *b, void *aux UNUSED)
{
	struct thread *st_a = list_entry(a, struct thread, donation_elem);
	struct thread *st_b = list_entry(b, struct thread, donation_elem);
	return st_a->priority > st_b->priority;
}

// 현재 스레드가 원하는 락을 가진 holder에게 현재 스레드의 priority 상속
void donate_priority(void)
{
	struct thread *curr = thread_current(); // 검사중인 스레드
	struct thread *holder;					// curr이 원하는 락을 가진드스레드

	int priority = curr->priority;

	for (int i = 0; i < 8; i++)
	{
		if (curr->wait_on_lock == NULL) // 더이상 중첩되지 않았으면 종료
			return;
		holder = curr->wait_on_lock->holder;
		if (holder->priority < priority)
			holder->priority = priority;
		curr = holder;
	}
}

// donors list를 돌면서 현재 release될 락을 기다리고 있던 donors를 삭제
void remove_donor(struct lock *lock)
{
	struct list *donations = &(thread_current()->donations); // 현재 스레드의 donations
	struct list_elem *donor_elem;							 // 현재 스레드의 donations의 요소
	struct thread *donor_thread;

	if (list_empty(donations))
		return;

	donor_elem = list_front(donations);

	while (1)
	{
		donor_thread = list_entry(donor_elem, struct thread, donation_elem);
		if (donor_thread->wait_on_lock == lock)		   // 현재 release될 lock을 기다리던 스레드라면
			list_remove(&donor_thread->donation_elem); // 목록에서 제거
		donor_elem = list_next(donor_elem);
		if (donor_elem == list_end(donations))
			return;
	}
}

// 락을 release하고 나서 priority를 상속 받기 이전 상태로 돌리는 함수
void update_priority_for_donations(void)
{
	struct thread *curr = thread_current();
	struct list *donations = &(thread_current()->donations);
	struct thread *donations_root;

	if (list_empty(donations)) // donors가 없으면 (donor가 하나였던 경우)
	{
		curr->priority = curr->init_priority; // 최초의 priority로 변경
		return;
	}

	donations_root = list_entry(list_front(donations), struct thread, donation_elem);
	curr->priority = donations_root->priority;
}