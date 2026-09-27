//! Reusable storage-based reentrancy guard for cross-contract calls.
//!
//! Any contract function that invokes an external contract can be re-entered:
//! the callee may call back into the same guarded function before its first
//! invocation has finished, observing half-updated state. This module provides
//! a lightweight mutual-exclusion lock, backed by instance storage, that such
//! functions wrap around their critical section.
//!
//! ## Usage
//!
//! ```ignore
//! use crate::reentrancy_guard::with_guard;
//!
//! pub fn do_external_call(env: &Env) -> Result<(), MyError> {
//!     with_guard(env, || {
//!         // ... perform the cross-contract call and state updates here ...
//!         Ok(())
//!     })
//! }
//! ```
//!
//! The lock lives in instance storage, so it is automatically rolled back if
//! the transaction panics — a failed guarded call can never leave the contract
//! permanently locked.
//!
//! ## Protection pattern (Issue #472)
//!
//! Every entry point that moves value or mutates balances follows the same
//! rules. New entry points in these modules should follow them too.
//!
//! 1. **Guard the whole entry point.** The lock is acquired *before*
//!    `require_auth`, because authorizing a custom-account address runs that
//!    account's `__check_auth` — an external call that could otherwise call
//!    back in before any state is written.
//! 2. **Checks → effects → interactions.** Inside the guard, validate first,
//!    write every state change next, and only then emit events or call out.
//!    Nothing is read back after an interaction.
//! 3. **One lock, entry points only.** The lock is a single global flag, so a
//!    guarded function cannot call another guarded function. Where one entry
//!    point composes another (e.g. `dex_integration::list_at_market` →
//!    `harvest_and_list` → `resource_minter::harvest_resources`), the reusable
//!    body lives in a `*_unguarded` function and the public wrapper is the only
//!    place that takes the lock.
//! 4. **A rejected re-entry never releases the outer lock.** [`with_guard`]
//!    returns before running its body when [`acquire`] fails, so the caller
//!    that actually holds the lock is the only one that releases it.
//!
//! Guarded entry points: `resource_minter` (`mint_resource`,
//! `harvest_resources`, `auto_list_on_dex`), `dex_integration`
//! (`harvest_and_list`, `cancel_listing`, `list_at_market`), `trading` (limit
//! orders, trade recording, pool creation, liquidity and swaps),
//! `escrow_trader` (initiate, confirm, complete, cancel), `nomad_bonding`
//! (bond lifecycle, essence accrual, yield claims) and `treasure_vault`
//! (deposit, claim).
//!
//! The Soroban host already refuses to re-enter a contract that is on the call
//! stack. This guard is defence in depth: it also covers same-contract
//! composition and keeps the invariant explicit in code and tests should that
//! host behaviour or the contract topology ever change.

use soroban_sdk::{contracterror, contracttype, Env};

/// Storage key for the reentrancy lock flag.
#[derive(Clone)]
#[contracttype]
pub enum GuardKey {
    /// Global reentrancy lock flag (instance storage, cheapest to read).
    ReentrancyLock,
}

/// Error raised when a guarded section is re-entered.
#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ReentrancyError {
    /// A guarded section was entered while another was still in progress.
    ReentrantCall = 1,
}

impl crate::error_standard::StandardContractError for ReentrancyError {
    fn descriptor(self) -> crate::error_standard::ErrorDescriptor {
        use crate::error_standard::ErrorKind;
        let (kind, retryable) = match self {
            Self::ReentrantCall => (ErrorKind::Conflict, false),
        };
        crate::error_standard::ErrorDescriptor {
            module: "reentrancy_guard",
            code: self as u32,
            kind,
            retryable,
        }
    }
}

/// Acquire the global reentrancy lock.
///
/// Returns [`ReentrancyError::ReentrantCall`] if the lock is already held,
/// which means an in-progress guarded section is being re-entered.
pub fn acquire(env: &Env) -> Result<(), ReentrancyError> {
    let locked: bool = env
        .storage()
        .instance()
        .get(&GuardKey::ReentrancyLock)
        .unwrap_or(false);
    if locked {
        return Err(ReentrancyError::ReentrantCall);
    }
    env.storage()
        .instance()
        .set(&GuardKey::ReentrancyLock, &true);
    Ok(())
}

/// Release the global reentrancy lock. Call only after a successful [`acquire`].
pub fn release(env: &Env) {
    env.storage()
        .instance()
        .set(&GuardKey::ReentrancyLock, &false);
}

/// Returns `true` while a guarded section is currently executing.
pub fn is_locked(env: &Env) -> bool {
    env.storage()
        .instance()
        .get(&GuardKey::ReentrancyLock)
        .unwrap_or(false)
}

/// Run `body` inside the reentrancy guard, releasing the lock afterwards.
///
/// The lock is released on both the success and error paths, so a guarded call
/// that returns an error never leaves the contract locked. Any error type that
/// can be built from [`ReentrancyError`] is supported, letting callers keep
/// their own domain error enum.
pub fn with_guard<T, E, F>(env: &Env, body: F) -> Result<T, E>
where
    F: FnOnce() -> Result<T, E>,
    E: From<ReentrancyError>,
{
    acquire(env).map_err(E::from)?;
    let result = body();
    release(env);
    result
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{contract, contractimpl, Env};

    #[contract]
    struct GuardTestContract;

    #[contractimpl]
    impl GuardTestContract {
        /// Runs a guarded section that attempts to re-enter the guard from
        /// within itself — simulating a malicious cross-contract callback.
        pub fn reenter(env: Env) -> Result<u32, ReentrancyError> {
            with_guard(&env, || {
                // Second acquire while still inside the guard must be rejected.
                acquire(&env)?;
                Ok(0u32)
            })
        }

        /// A normal guarded call that does no re-entry.
        pub fn single(env: Env) -> Result<u32, ReentrancyError> {
            with_guard(&env, || Ok(42u32))
        }

        /// A guarded call whose body fails.
        pub fn failing(env: Env) -> Result<u32, ReentrancyError> {
            with_guard(&env, || Err(ReentrancyError::ReentrantCall))
        }

        /// Exposes the lock flag so tests can assert it is released.
        pub fn locked(env: Env) -> bool {
            is_locked(&env)
        }
    }

    #[test]
    fn blocks_reentrant_call() {
        let env = Env::default();
        let id = env.register(GuardTestContract, ());
        let client = GuardTestContractClient::new(&env, &id);
        // The re-entrant attempt surfaces as a contract error.
        assert_eq!(client.try_reenter(), Err(Ok(ReentrancyError::ReentrantCall)));
    }

    #[test]
    fn allows_sequential_calls_and_releases_lock() {
        let env = Env::default();
        let id = env.register(GuardTestContract, ());
        let client = GuardTestContractClient::new(&env, &id);

        assert_eq!(client.single(), 42);
        // Lock must be released once the guarded call completes.
        assert_eq!(client.locked(), false);
        // A subsequent call still succeeds (the guard is not stuck).
        assert_eq!(client.single(), 42);
    }

    #[test]
    fn releases_lock_when_body_errors() {
        let env = Env::default();
        let id = env.register(GuardTestContract, ());
        let client = GuardTestContractClient::new(&env, &id);

        assert!(client.try_failing().is_err());
        assert!(!client.locked());
        assert_eq!(client.single(), 42);
    }

    #[test]
    fn rejected_reentry_does_not_release_outer_lock() {
        let env = Env::default();
        let id = env.register(GuardTestContract, ());

        env.as_contract(&id, || {
            acquire(&env).expect("lock should be free");

            // The nested attempt is rejected...
            let nested: Result<(), ReentrancyError> = with_guard(&env, || Ok(()));
            assert_eq!(nested, Err(ReentrancyError::ReentrantCall));
            // ...and must not have freed the lock the outer caller still holds.
            assert!(is_locked(&env));

            release(&env);
            assert!(!is_locked(&env));
        });
    }
}
