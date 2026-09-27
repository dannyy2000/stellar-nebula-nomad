//! Reentrancy attack tests for every guarded entry point (Issue #472).
//!
//! Each test simulates an attacker's callback landing while a first
//! invocation is still in flight: the reentrancy lock is taken (as the
//! in-flight call would hold it), then the guarded entry point is invoked. The
//! test asserts that the nested call is
//!
//! 1. rejected with the module's `Reentrancy` error,
//! 2. rejected *before* any state is written (balances, orders, pools, escrows,
//!    bonds and vaults are unchanged), and
//! 3. unable to release the lock held by the in-flight call.
//!
//! Once the lock is released the same call succeeds, which proves the guard
//! does not leave the contract stuck.
//!
//! Every step runs as its own contract invocation because `mock_all_auths`
//! only authorizes an address once per invocation.

use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Bytes, BytesN, Env, Symbol, Vec};

use crate::escrow_trader::{self, EscrowError, TradeAsset};
use crate::nebula_explorer::{CellType, NebulaCell, NebulaLayout};
use crate::nomad_bonding::{self, BondError, BondStatus};
use crate::reentrancy_guard;
use crate::resource_minter::{
    self, HarvestError, MinterError, ResourceMinterContract, ResourceType,
};
use crate::trading::{self, AmmError, LimitOrder, OrderSide, TradeRecord, TradingError};
use crate::treasure_vault::{self, VaultError};
use crate::{dex_integration, ship_nft};

#[contract]
struct Stub;

#[contractimpl]
impl Stub {}

struct Harness {
    env: Env,
    id: Address,
}

impl Harness {
    fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register(Stub, ());
        Self { env, id }
    }

    fn addr(&self) -> Address {
        Address::generate(&self.env)
    }

    /// Perform one contract invocation.
    fn invoke<T>(&self, f: impl FnOnce(&Env) -> T) -> T {
        self.env.as_contract(&self.id, || f(&self.env))
    }

    /// Run `f` while an in-flight call holds the lock, then check that the
    /// rejected attempt left that lock in place before releasing it.
    fn while_locked<T>(&self, f: impl FnOnce(&Env) -> T) -> T {
        self.invoke(|env| reentrancy_guard::acquire(env).expect("lock should be free"));
        let out = self.invoke(f);
        self.invoke(|env| {
            assert!(
                reentrancy_guard::is_locked(env),
                "a rejected re-entry must not release the in-flight call's lock"
            );
            reentrancy_guard::release(env);
        });
        out
    }

    fn assert_unlocked(&self) {
        self.invoke(|env| assert!(!reentrancy_guard::is_locked(env)));
    }
}

// ── Fixtures ────────────────────────────────────────────────────────────────

const ENERGY: u32 = 40;

fn dust() -> Symbol {
    symbol_short!("dust")
}

fn dust_layout(env: &Env) -> NebulaLayout {
    let mut cells = Vec::new(env);
    cells.push_back(NebulaCell {
        x: 0,
        y: 0,
        cell_type: CellType::StellarDust,
        energy: ENERGY,
    });
    NebulaLayout {
        width: 1,
        height: 1,
        cells,
        seed: BytesN::from_array(env, &[7u8; 32]),
        timestamp: 0,
        total_energy: ENERGY,
    }
}

fn mint_ship(h: &Harness, owner: &Address) -> u64 {
    h.invoke(|env| {
        ship_nft::mint_ship(env, owner, &symbol_short!("explorer"), &Bytes::new(env))
            .unwrap()
            .id
    })
}

fn limit_order(env: &Env, trader: &Address) -> LimitOrder {
    LimitOrder {
        id: 0,
        trader: trader.clone(),
        side: OrderSide::Buy,
        resource: symbol_short!("stdust"),
        quantity: 10,
        limit_price: 5,
        placed_at: env.ledger().timestamp(),
        is_stop_loss: false,
    }
}

fn seeded_pool(h: &Harness, provider: &Address) -> u64 {
    let pool_id = h.invoke(|env| {
        trading::create_pool(
            env,
            provider,
            symbol_short!("stdust"),
            symbol_short!("drmatt"),
        )
        .unwrap()
    });
    h.invoke(|env| trading::add_liquidity(env, provider, pool_id, 10_000, 10_000).unwrap());
    pool_id
}

fn assets(env: &Env, asset_type: &str, quantity: i128) -> Vec<TradeAsset> {
    let mut v = Vec::new(env);
    v.push_back(TradeAsset {
        asset_type: Symbol::new(env, asset_type),
        asset_id: 1,
        quantity,
    });
    v
}

fn open_escrow(h: &Harness, a: &Address, b: &Address) -> u64 {
    h.invoke(|env| {
        escrow_trader::initiate_escrow(
            env,
            a.clone(),
            b.clone(),
            assets(env, "ship", 1),
            assets(env, "essence", 100),
        )
        .unwrap()
        .escrow_id
    })
}

fn active_bond(h: &Harness, initiator: &Address, partner: &Address) -> u64 {
    let bond_id = h.invoke(|env| {
        nomad_bonding::create_bond(env, initiator, 1, partner)
            .unwrap()
            .bond_id
    });
    h.invoke(|env| nomad_bonding::accept_bond(env, partner, bond_id).unwrap());
    bond_id
}

// ── resource_minter ─────────────────────────────────────────────────────────

#[test]
fn mint_resource_blocks_reentry() {
    let h = Harness::new();
    let caller = h.addr();
    let contract = h.env.register(ResourceMinterContract, ());

    h.env
        .as_contract(&contract, || reentrancy_guard::acquire(&h.env).unwrap());
    let result = h.env.as_contract(&contract, || {
        ResourceMinterContract::mint_resource(
            &h.env,
            caller.clone(),
            1,
            0,
            ResourceType::StellarDust,
            5,
        )
    });
    assert_eq!(result, Err(MinterError::Reentrancy));

    h.env.as_contract(&contract, || {
        assert!(reentrancy_guard::is_locked(&h.env));
        assert_eq!(
            ResourceMinterContract::balance(&h.env, caller.clone(), ResourceType::StellarDust),
            0
        );
        assert_eq!(
            ResourceMinterContract::total_supply(&h.env, ResourceType::StellarDust),
            0
        );
    });
}

#[test]
fn harvest_resources_blocks_reentry_then_recovers() {
    let h = Harness::new();
    let owner = h.addr();
    let ship_id = mint_ship(&h, &owner);

    let result =
        h.while_locked(|env| resource_minter::harvest_resources(env, ship_id, &dust_layout(env)));
    assert_eq!(result, Err(HarvestError::Reentrancy));
    h.invoke(|env| assert_eq!(resource_minter::resource_balance(env, &owner, &dust()), 0));

    // Unlocked, the same harvest succeeds and the lock is released afterwards.
    let harvested = h
        .invoke(|env| resource_minter::harvest_resources(env, ship_id, &dust_layout(env)))
        .unwrap();
    assert_eq!(harvested.total_harvested, ENERGY);
    h.assert_unlocked();
}

#[test]
fn auto_list_on_dex_blocks_reentry() {
    let h = Harness::new();
    let owner = h.addr();
    let ship_id = mint_ship(&h, &owner);
    h.invoke(|env| resource_minter::harvest_resources(env, ship_id, &dust_layout(env)).unwrap());

    let result = h.while_locked(|env| resource_minter::auto_list_on_dex(env, &owner, &dust(), 5));
    assert_eq!(result, Err(HarvestError::Reentrancy));

    // The escrow debit never happened and no offer was created.
    h.invoke(|env| {
        assert_eq!(
            resource_minter::resource_balance(env, &owner, &dust()),
            ENERGY
        );
        assert!(resource_minter::get_dex_offer(env, 1).is_none());
    });
}

// ── dex_integration ─────────────────────────────────────────────────────────

#[test]
fn harvest_and_list_blocks_reentry() {
    let h = Harness::new();
    let owner = h.addr();
    let ship_id = mint_ship(&h, &owner);

    let result = h.while_locked(|env| {
        dex_integration::harvest_and_list(env, &owner, ship_id, &dust_layout(env), &dust(), 5)
    });
    assert_eq!(result.err(), Some(HarvestError::Reentrancy));

    // The inner harvest did not run either: nothing credited, nothing listed.
    h.invoke(|env| {
        assert_eq!(resource_minter::resource_balance(env, &owner, &dust()), 0);
        assert!(dex_integration::get_offer(env, 1).is_none());
    });
}

#[test]
fn harvest_and_list_composes_without_self_locking() {
    // `harvest_and_list` calls the harvest body internally. With a single
    // global lock that nested call must use the unguarded body, otherwise
    // every legitimate harvest-and-list would fail with `Reentrancy`.
    let h = Harness::new();
    let owner = h.addr();
    let ship_id = mint_ship(&h, &owner);

    let (harvest, offer) = h
        .invoke(|env| {
            dex_integration::harvest_and_list(env, &owner, ship_id, &dust_layout(env), &dust(), 5)
        })
        .unwrap();
    assert_eq!(harvest.total_harvested, ENERGY);
    assert_eq!(offer.amount, ENERGY);
    h.assert_unlocked();
}

#[test]
fn cancel_listing_blocks_reentry_and_keeps_escrow() {
    let h = Harness::new();
    let owner = h.addr();
    let ship_id = mint_ship(&h, &owner);
    let (_, offer) = h
        .invoke(|env| {
            dex_integration::harvest_and_list(env, &owner, ship_id, &dust_layout(env), &dust(), 5)
        })
        .unwrap();

    // A re-entrant cancel must not refund the escrow a second time.
    let result = h.while_locked(|env| dex_integration::cancel_listing(env, &owner, offer.offer_id));
    assert_eq!(result, Err(HarvestError::Reentrancy));
    h.invoke(|env| {
        assert!(
            dex_integration::get_offer(env, offer.offer_id)
                .unwrap()
                .active
        );
        assert_eq!(resource_minter::resource_balance(env, &owner, &dust()), 0);
    });

    // Unlocked, cancelling refunds exactly once.
    h.invoke(|env| dex_integration::cancel_listing(env, &owner, offer.offer_id).unwrap());
    h.invoke(|env| {
        assert_eq!(
            resource_minter::resource_balance(env, &owner, &dust()),
            ENERGY
        )
    });
}

#[test]
fn list_at_market_blocks_reentry() {
    let h = Harness::new();
    let owner = h.addr();
    let ship_id = mint_ship(&h, &owner);

    let result = h.while_locked(|env| {
        dex_integration::list_at_market(env, &owner, ship_id, &dust_layout(env), &dust())
    });
    assert_eq!(
        result.err(),
        Some(dex_integration::DynamicListError::Reentrancy)
    );
    h.invoke(|env| assert_eq!(resource_minter::resource_balance(env, &owner, &dust()), 0));
}

// ── trading: limit orders ───────────────────────────────────────────────────

#[test]
fn place_limit_order_blocks_reentry() {
    let h = Harness::new();
    let trader = h.addr();

    let result =
        h.while_locked(|env| trading::place_limit_order(env, &trader, limit_order(env, &trader)));
    assert_eq!(result, Err(TradingError::Reentrancy));
    h.invoke(|env| assert!(trading::get_trader_orders(env, &trader).is_empty()));
}

#[test]
fn cancel_limit_order_blocks_reentry() {
    let h = Harness::new();
    let trader = h.addr();
    let order_id = h
        .invoke(|env| trading::place_limit_order(env, &trader, limit_order(env, &trader)))
        .unwrap();

    let result = h.while_locked(|env| trading::cancel_limit_order(env, &trader, order_id));
    assert_eq!(result, Err(TradingError::Reentrancy));
    h.invoke(|env| assert!(trading::get_limit_order(env, order_id).is_some()));
}

#[test]
fn record_trade_blocks_reentry() {
    let h = Harness::new();
    let trader = h.addr();

    let result = h.while_locked(|env| {
        let trade = TradeRecord {
            order_id: 1,
            trader: trader.clone(),
            side: OrderSide::Sell,
            resource: symbol_short!("stdust"),
            quantity: 1,
            price: 1,
            executed_at: 0,
        };
        trading::record_trade(env, &trader, trade)
    });
    assert_eq!(result, Err(TradingError::Reentrancy));
    h.invoke(|env| assert!(trading::get_trading_history(env).is_empty()));
}

// ── trading: AMM ────────────────────────────────────────────────────────────

#[test]
fn create_pool_blocks_reentry() {
    let h = Harness::new();
    let creator = h.addr();

    let result = h.while_locked(|env| {
        trading::create_pool(
            env,
            &creator,
            symbol_short!("stdust"),
            symbol_short!("drmatt"),
        )
    });
    assert_eq!(result, Err(AmmError::Reentrancy));
    h.invoke(|env| assert!(trading::get_all_pools(env).is_empty()));
}

#[test]
fn add_liquidity_blocks_reentry() {
    let h = Harness::new();
    let provider = h.addr();
    let pool_id = seeded_pool(&h, &provider);

    let result = h.while_locked(|env| trading::add_liquidity(env, &provider, pool_id, 500, 500));
    assert_eq!(result.err(), Some(AmmError::Reentrancy));
    h.invoke(|env| {
        let pool = trading::get_pool(env, pool_id).unwrap();
        assert_eq!((pool.reserve_a, pool.reserve_b), (10_000, 10_000));
    });
}

#[test]
fn remove_liquidity_blocks_reentry() {
    let h = Harness::new();
    let provider = h.addr();
    let pool_id = seeded_pool(&h, &provider);
    let lp = h.invoke(|env| trading::get_lp_balance(env, pool_id, &provider));

    // A re-entrant withdrawal must not pay out the same LP tokens twice.
    let result = h.while_locked(|env| trading::remove_liquidity(env, &provider, pool_id, lp));
    assert_eq!(result, Err(AmmError::Reentrancy));
    h.invoke(|env| {
        assert_eq!(trading::get_lp_balance(env, pool_id, &provider), lp);
        let pool = trading::get_pool(env, pool_id).unwrap();
        assert_eq!((pool.reserve_a, pool.reserve_b), (10_000, 10_000));
    });
}

#[test]
fn swap_exact_input_blocks_reentry() {
    let h = Harness::new();
    let provider = h.addr();
    let trader = h.addr();
    let pool_id = seeded_pool(&h, &provider);

    let result = h.while_locked(|env| {
        let mut route = Vec::new(env);
        route.push_back(pool_id);
        trading::swap_exact_input(env, &trader, symbol_short!("stdust"), 100, 0, route)
    });
    assert_eq!(result, Err(AmmError::Reentrancy));
    h.invoke(|env| {
        let pool = trading::get_pool(env, pool_id).unwrap();
        assert_eq!((pool.reserve_a, pool.reserve_b), (10_000, 10_000));
    });
}

// ── escrow_trader ───────────────────────────────────────────────────────────

#[test]
fn initiate_escrow_blocks_reentry() {
    let h = Harness::new();
    let (a, b) = (h.addr(), h.addr());

    let result = h.while_locked(|env| {
        escrow_trader::initiate_escrow(
            env,
            a.clone(),
            b.clone(),
            assets(env, "ship", 1),
            assets(env, "essence", 100),
        )
    });
    assert_eq!(result, Err(EscrowError::Reentrancy));
    h.invoke(|env| assert!(escrow_trader::get_escrow(env, 1).is_none()));
}

#[test]
fn confirm_escrow_blocks_reentry() {
    let h = Harness::new();
    let (a, b) = (h.addr(), h.addr());
    let escrow_id = open_escrow(&h, &a, &b);

    let result = h.while_locked(|env| escrow_trader::confirm_escrow(env, escrow_id, b.clone()));
    assert_eq!(result, Err(EscrowError::Reentrancy));
    h.invoke(|env| {
        assert!(
            !escrow_trader::get_escrow(env, escrow_id)
                .unwrap()
                .confirmed_b
        )
    });
}

#[test]
fn complete_escrow_blocks_reentry_and_settles_once() {
    let h = Harness::new();
    let (a, b) = (h.addr(), h.addr());
    let escrow_id = open_escrow(&h, &a, &b);
    h.invoke(|env| escrow_trader::confirm_escrow(env, escrow_id, b.clone()).unwrap());

    let result = h.while_locked(|env| escrow_trader::complete_escrow(env, escrow_id));
    assert_eq!(result, Err(EscrowError::Reentrancy));
    h.invoke(|env| assert!(!escrow_trader::get_escrow(env, escrow_id).unwrap().completed));

    h.invoke(|env| escrow_trader::complete_escrow(env, escrow_id).unwrap());
    let again = h.invoke(|env| escrow_trader::complete_escrow(env, escrow_id));
    assert_eq!(again, Err(EscrowError::AlreadyConfirmed));
}

#[test]
fn cancel_escrow_blocks_reentry() {
    let h = Harness::new();
    let (a, b) = (h.addr(), h.addr());
    let escrow_id = open_escrow(&h, &a, &b);

    let result = h.while_locked(|env| escrow_trader::cancel_escrow(env, escrow_id, a.clone()));
    assert_eq!(result, Err(EscrowError::Reentrancy));
    h.invoke(|env| assert!(escrow_trader::get_escrow(env, escrow_id).is_some()));
}

// ── nomad_bonding ───────────────────────────────────────────────────────────

#[test]
fn bond_creation_and_acceptance_block_reentry() {
    let h = Harness::new();
    let (initiator, partner) = (h.addr(), h.addr());

    let result = h.while_locked(|env| nomad_bonding::create_bond(env, &initiator, 1, &partner));
    assert_eq!(result, Err(BondError::Reentrancy));
    h.invoke(|env| {
        assert_eq!(
            nomad_bonding::get_bond(env, 1),
            Err(BondError::BondNotFound)
        )
    });

    let bond_id = h.invoke(|env| {
        nomad_bonding::create_bond(env, &initiator, 1, &partner)
            .unwrap()
            .bond_id
    });
    let result = h.while_locked(|env| nomad_bonding::accept_bond(env, &partner, bond_id));
    assert_eq!(result, Err(BondError::Reentrancy));
    h.invoke(|env| {
        assert_eq!(
            nomad_bonding::get_bond(env, bond_id).unwrap().status,
            BondStatus::Pending
        );
    });
}

#[test]
fn delegate_and_accrue_block_reentry() {
    let h = Harness::new();
    let (initiator, partner) = (h.addr(), h.addr());
    let bond_id = active_bond(&h, &initiator, &partner);

    let result = h.while_locked(|env| nomad_bonding::delegate_yield(env, &initiator, bond_id, 50));
    assert_eq!(result, Err(BondError::Reentrancy));
    h.invoke(|env| {
        assert_eq!(
            nomad_bonding::get_yield_delegation(env, bond_id),
            Err(BondError::NoDelegation)
        );
    });

    let result = h.while_locked(|env| nomad_bonding::accrue_essence(env, &initiator, 1_000));
    assert_eq!(result, Err(BondError::Reentrancy));
    h.invoke(|env| assert_eq!(nomad_bonding::get_essence_balance(env, &initiator), 0));
}

#[test]
fn claim_yield_blocks_reentry_and_pays_once() {
    let h = Harness::new();
    let (initiator, partner) = (h.addr(), h.addr());
    let bond_id = active_bond(&h, &initiator, &partner);
    h.invoke(|env| nomad_bonding::delegate_yield(env, &initiator, bond_id, 50).unwrap());
    h.invoke(|env| nomad_bonding::accrue_essence(env, &initiator, 1_000).unwrap());

    // The classic drain: re-enter the claim before the first one has debited
    // the delegator. The nested claim must pay nothing.
    let result = h.while_locked(|env| nomad_bonding::claim_yield(env, &partner, bond_id));
    assert_eq!(result, Err(BondError::Reentrancy));
    h.invoke(|env| {
        assert_eq!(nomad_bonding::get_essence_balance(env, &initiator), 1_000);
        assert_eq!(nomad_bonding::get_essence_balance(env, &partner), 0);
    });

    let paid = h.invoke(|env| nomad_bonding::claim_yield(env, &partner, bond_id).unwrap());
    assert_eq!(paid, 500);
    h.invoke(|env| {
        assert_eq!(nomad_bonding::get_essence_balance(env, &initiator), 500);
        assert_eq!(nomad_bonding::get_essence_balance(env, &partner), 500);
    });
}

#[test]
fn dissolve_bond_blocks_reentry() {
    let h = Harness::new();
    let (initiator, partner) = (h.addr(), h.addr());
    let bond_id = active_bond(&h, &initiator, &partner);

    let result = h.while_locked(|env| nomad_bonding::dissolve_bond(env, &initiator, bond_id));
    assert_eq!(result, Err(BondError::Reentrancy));
    h.invoke(|env| {
        assert_eq!(
            nomad_bonding::get_bond(env, bond_id).unwrap().status,
            BondStatus::Active
        );
    });
}

// ── treasure_vault ──────────────────────────────────────────────────────────

#[test]
fn deposit_treasure_blocks_reentry() {
    let h = Harness::new();
    let owner = h.addr();

    let result = h.while_locked(|env| treasure_vault::deposit_treasure(env, &owner, 1, 500));
    assert_eq!(result.err(), Some(VaultError::Reentrancy));
    h.invoke(|env| assert!(treasure_vault::get_vault(env, 1).is_none()));
}

#[test]
fn claim_treasure_blocks_reentry_and_pays_once() {
    let h = Harness::new();
    let owner = h.addr();
    let vault_id = h.invoke(|env| {
        treasure_vault::deposit_treasure(env, &owner, 1, 500)
            .unwrap()
            .vault_id
    });
    h.env
        .ledger()
        .with_mut(|l| l.timestamp += treasure_vault::DEFAULT_MIN_LOCK_DURATION + 1);

    let result = h.while_locked(|env| treasure_vault::claim_treasure(env, &owner, vault_id));
    assert_eq!(result, Err(VaultError::Reentrancy));
    h.invoke(|env| assert!(!treasure_vault::get_vault(env, vault_id).unwrap().claimed));

    let payout = h.invoke(|env| treasure_vault::claim_treasure(env, &owner, vault_id).unwrap());
    assert_eq!(payout, 550);
    let again = h.invoke(|env| treasure_vault::claim_treasure(env, &owner, vault_id));
    assert_eq!(again, Err(VaultError::AlreadyClaimed));
    h.assert_unlocked();
}
