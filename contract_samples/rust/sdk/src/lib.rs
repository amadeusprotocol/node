#![cfg_attr(not(any(test, feature = "testing")), no_std)]
#![cfg_attr(any(test, feature = "testing"), feature(thread_local))]
#![allow(unused_imports)]

extern crate alloc;

#[cfg(any(test, feature = "testing"))]
extern crate std;

pub mod context;
pub mod storage;
pub mod encoding;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use context::*;
pub use storage::*;
pub use encoding::*;
pub use amadeus_sdk_macros::{contract, contract_state};

use alloc::vec;

pub trait ContractState {
    fn with_prefix(prefix: Vec<u8>) -> Self;
    fn flush(&self);
}

use core::panic::PanicInfo;

use alloc::{borrow::Cow, vec::Vec, string::String, string::ToString};


#[cfg(not(any(test, feature = "testing")))]
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}

#[cfg(all(feature = "use-dlmalloc", not(any(test, feature = "testing"))))]
#[global_allocator]
static ALLOC: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;

#[macro_export]
macro_rules! assert {
    ($cond:expr, $msg:expr) => {
        if !$cond {
            $crate::context::log($msg);

            #[cfg(target_arch = "wasm32")]
            core::arch::wasm32::unreachable();
        }
    };
}

#[macro_export]
macro_rules! abort {
    ($msg:expr) => {
        {
            $crate::context::log($msg);

            #[cfg(all(target_arch = "wasm32", not(test)))]
            core::arch::wasm32::unreachable();

            #[cfg(test)]
            panic!($msg);

            #[allow(unreachable_code)]
            loop {}
        }
    };
}

#[macro_export]
macro_rules! b {
    ( $( $x:expr ),* ) => {
        {
            let mut temp_vec = alloc::vec::Vec::new();
            $(
                temp_vec.extend_from_slice($x.as_ref());
            )*
            temp_vec
        }
    };
}

macro_rules! impl_payload_for_ints {
    ( $($t:ty),* ) => {
        $(
            impl Payload for $t {
                fn to_payload<'a>(&'a self) -> Cow<'a, [u8]> {
                    Cow::Owned(self.to_string().into_bytes())
                }
            }
        )*
    };
}

pub trait Payload {
    fn to_payload<'a>(&'a self) -> Cow<'a, [u8]>;
}

impl Payload for &str {
    fn to_payload<'a>(&'a self) -> Cow<'a, [u8]> { Cow::Borrowed(self.as_bytes()) }
}

impl Payload for String {
    fn to_payload<'a>(&'a self) -> Cow<'a, [u8]> { Cow::Borrowed(self.as_bytes()) }
}

impl Payload for &[u8] {
    fn to_payload<'a>(&'a self) -> Cow<'a, [u8]> { Cow::Borrowed(self) }
}

impl Payload for Vec<u8> {
    fn to_payload<'a>(&'a self) -> Cow<'a, [u8]> { Cow::Borrowed(self.as_slice()) }
}

impl Payload for &alloc::vec::Vec<u8> {
    fn to_payload<'a>(&'a self) -> alloc::borrow::Cow<'a, [u8]> {
        alloc::borrow::Cow::Borrowed(self.as_slice())
    }
}

impl_payload_for_ints!(u8, u16, u32, u64, u128, usize);
impl_payload_for_ints!(i8, i16, i32, i64, i128, isize);

pub struct LazyCell<T> {
    key: Vec<u8>,
    value: core::cell::RefCell<Option<T>>,
    dirty: core::cell::Cell<bool>,
}

impl<T> core::ops::Deref for LazyCell<T>
where
    T: FromKvBytes + Default + Clone
{
    type Target = T;

    fn deref(&self) -> &T {
        if self.value.borrow().is_none() {
            let loaded = kv_get::<T>(&self.key).unwrap_or_default();
            *self.value.borrow_mut() = Some(loaded);
        }
        unsafe {
            (*self.value.as_ptr()).as_ref().unwrap()
        }
    }
}

impl<T> core::ops::DerefMut for LazyCell<T>
where
    T: FromKvBytes + Default + Clone
{
    fn deref_mut(&mut self) -> &mut T {
        if self.value.borrow().is_none() {
            let loaded = kv_get::<T>(&self.key).unwrap_or_default();
            *self.value.borrow_mut() = Some(loaded);
        }
        self.dirty.set(true);
        unsafe {
            (*self.value.as_ptr()).as_mut().unwrap()
        }
    }
}


impl<T: Payload + Clone> ContractState for LazyCell<T> {
    fn with_prefix(prefix: Vec<u8>) -> Self {
        Self {
            key: prefix,
            value: core::cell::RefCell::new(None),
            dirty: core::cell::Cell::new(false),
        }
    }

    fn flush(&self) {
        if self.dirty.get() {
            if let Some(val) = self.value.borrow().as_ref() {
                kv_put(&self.key, val.clone());
            }
        }
    }
}

impl<T> LazyCell<T> {
    pub fn get(&self) -> T where T: FromKvBytes + Default + Clone {
        if self.value.borrow().is_none() {
            let loaded = kv_get::<T>(&self.key).unwrap_or_default();
            *self.value.borrow_mut() = Some(loaded);
        }
        self.value.borrow().as_ref().unwrap().clone()
    }

    pub fn set(&self, val: T) {
        *self.value.borrow_mut() = Some(val);
        self.dirty.set(true);
    }

    pub fn update<F>(&self, f: F) where T: FromKvBytes + Default + Clone, F: FnOnce(T) -> T {
        let current = self.get();
        let new_value = f(current);
        self.set(new_value);
    }

    pub fn add(&self, amount: T) where T: FromKvBytes + Default + Clone + core::ops::Add<Output = T> {
        let current = self.get();
        self.set(current + amount);
    }
}

impl<T: ContractState + Default> LazyCell<T> {

    pub fn with_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R
    {
        if self.value.borrow().is_none() {
            let loaded = T::with_prefix(self.key.clone());
            *self.value.borrow_mut() = Some(loaded);
        }
        self.dirty.set(true);
        unsafe {
            let ptr = self.value.as_ptr();
            f((*ptr).as_mut().unwrap())
        }
    }

    pub fn with<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&T) -> R
    {
        if self.value.borrow().is_none() {
            let loaded = T::with_prefix(self.key.clone());
            *self.value.borrow_mut() = Some(loaded);
        }
        unsafe {
            let ptr = self.value.as_ptr();
            f((*ptr).as_ref().unwrap())
        }
    }
}

use alloc::collections::BTreeMap;

pub struct MapFlat<K, V> {
    prefix: Vec<u8>,
    cache: core::cell::UnsafeCell<BTreeMap<Vec<u8>, LazyCell<V>>>,
    _phantom: core::marker::PhantomData<K>,
}

impl<K, V> MapFlat<K, V>
where
    K: Payload,
    V: FromKvBytes + Payload + Default + Clone
{
    fn build_key(&self, key: &K) -> Vec<u8> {
        let key_bytes = key.to_payload();
        b!(self.prefix.as_slice(), key_bytes.as_ref())
    }

    pub fn get(&self, key: &K) -> Option<&LazyCell<V>> {
        let storage_key = self.build_key(key);
        unsafe {
            let cache = &mut *self.cache.get();
            if !cache.contains_key(&storage_key) {
                if kv_exists(&storage_key) {
                    cache.insert(storage_key.clone(), LazyCell::with_prefix(storage_key.clone()));
                } else {
                    return None;
                }
            }
            cache.get(&storage_key)
        }
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut LazyCell<V>> {
        let storage_key = self.build_key(key);

        unsafe {
            let cache = &mut *self.cache.get();
            if !cache.contains_key(&storage_key) {
                if kv_exists(&storage_key) {
                    cache.insert(storage_key.clone(), LazyCell::with_prefix(storage_key.clone()));
                } else {
                    return None;
                }
            }

            cache.get_mut(&storage_key)
        }
    }

    pub fn insert(&mut self, key: K, value: V) {
        let storage_key = self.build_key(&key);
        let cell: LazyCell<V> = LazyCell::with_prefix(storage_key.clone());
        cell.set(value);
        unsafe {
            (*self.cache.get()).insert(storage_key, cell);
        }
    }

    pub fn remove(&mut self, key: &K) {
        let storage_key = self.build_key(key);
        unsafe {
            (*self.cache.get()).remove(&storage_key);
        }
        kv_delete(&storage_key);
    }
}

impl<K, V> ContractState for MapFlat<K, V>
where
    K: Payload,
    V: FromKvBytes + Payload + Default + Clone
{
    fn with_prefix(prefix: Vec<u8>) -> Self {
        Self {
            prefix,
            cache: core::cell::UnsafeCell::new(BTreeMap::new()),
            _phantom: core::marker::PhantomData,
        }
    }

    fn flush(&self) {
        unsafe {
            for cell in (*self.cache.get()).values() {
                cell.flush();
            }
        }
    }
}

pub struct Map<K, V> {
    prefix: Vec<u8>,
    cache: core::cell::UnsafeCell<BTreeMap<Vec<u8>, V>>,
    _phantom: core::marker::PhantomData<K>,
}

pub struct MapIter<'a, K, V> {
    map: &'a Map<K, V>,
    keys: Vec<Vec<u8>>,
    index: usize,
}

impl<'a, K, V> Iterator for MapIter<'a, K, V>
where
    V: ContractState
{
    type Item = &'a V;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.keys.len() {
            return None;
        }

        let key = &self.keys[self.index];
        self.index += 1;

        unsafe {
            let cache = &*self.map.cache.get();
            cache.get(key).map(|v| &*(v as *const V))
        }
    }
}

pub struct MapIterMut<'a, K, V> {
    map: &'a Map<K, V>,
    keys: Vec<Vec<u8>>,
    index: usize,
}

impl<'a, K, V> Iterator for MapIterMut<'a, K, V>
where
    V: ContractState
{
    type Item = &'a mut V;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.keys.len() {
            return None;
        }

        let key = &self.keys[self.index];
        self.index += 1;

        unsafe {
            let cache = &mut *self.map.cache.get();
            cache.get_mut(key).map(|v| &mut *(v as *mut V))
        }
    }
}

impl<K, V> Map<K, V>
where
    K: Payload,
    V: ContractState
{
    fn build_key(&self, key: &K) -> Vec<u8> {
        let key_bytes = key.to_payload();
        b!(self.prefix.as_slice(), key_bytes.as_ref())
    }

    pub fn get(&self, key: K) -> Option<&V> {
        let storage_key = self.build_key(&key);

        unsafe {
            let cache = &mut *self.cache.get();
            if !cache.contains_key(&storage_key) {
                // Cannot use kv_exists() because V is a ContractState (not a single value).
                // ContractState uses the key as a prefix for nested fields, so we check if
                // any keys exist with this prefix using kv_get_next().
                let (first_key, _) = kv_get_next(&storage_key, &vec![]);
                if first_key.is_some() {
                    let value = V::with_prefix(storage_key.clone());
                    cache.insert(storage_key.clone(), value);
                } else {
                    return None;
                }
            }

            cache.get(&storage_key).map(|v| &*(v as *const V))
        }
    }

    pub fn get_mut(&mut self, key: K) -> Option<&mut V> {
        let storage_key = self.build_key(&key);

        unsafe {
            let cache = &mut *self.cache.get();
            if !cache.contains_key(&storage_key) {
                // Cannot use kv_exists() because V is a ContractState (not a single value).
                // ContractState uses the key as a prefix for nested fields, so we check if
                // any keys exist with this prefix using kv_get_next().
                let (first_key, _) = kv_get_next(&storage_key, &vec![]);
                if first_key.is_some() {
                    let value = V::with_prefix(storage_key.clone());
                    cache.insert(storage_key.clone(), value);
                } else {
                    return None;
                }
            }

            cache.get_mut(&storage_key)
        }
    }

    pub fn with(&self) -> MapIter<'_, K, V> {
        let mut keys = Vec::new();
        let mut current_key = vec![];

        unsafe {
            let cache = &mut *self.cache.get();

            loop {
                let (key, _) = kv_get_next(&self.prefix, &current_key);
                match key {
                    Some(k) => {
                        if !cache.contains_key(&k) {
                            let value = V::with_prefix(k.clone());
                            cache.insert(k.clone(), value);
                        }
                        keys.push(k.clone());
                        current_key = k;
                    }
                    None => break,
                }
            }
        }

        MapIter {
            map: self,
            keys,
            index: 0,
        }
    }

    pub fn with_mut(&mut self) -> MapIterMut<'_, K, V> {
        let mut keys = Vec::new();
        let mut current_key = vec![];

        unsafe {
            let cache = &mut *self.cache.get();

            loop {
                let (key, _) = kv_get_next(&self.prefix, &current_key);
                match key {
                    Some(k) => {
                        if !cache.contains_key(&k) {
                            let value = V::with_prefix(k.clone());
                            cache.insert(k.clone(), value);
                        }
                        keys.push(k.clone());
                        current_key = k;
                    }
                    None => break,
                }
            }
        }

        MapIterMut {
            map: self,
            keys,
            index: 0,
        }
    }

    pub fn insert(&mut self, key: K, value: V) {
        let storage_key = self.build_key(&key);
        unsafe {
            (*self.cache.get()).insert(storage_key, value);
        }
    }

    pub fn remove(&mut self, key: &K) {
        let storage_key = self.build_key(key);
        unsafe {
            (*self.cache.get()).remove(&storage_key);
        }
    }
}

impl<K, V> ContractState for Map<K, V>
where
    K: Payload,
    V: ContractState
{
    fn with_prefix(prefix: Vec<u8>) -> Self {
        Self {
            prefix,
            cache: core::cell::UnsafeCell::new(BTreeMap::new()),
            _phantom: core::marker::PhantomData,
        }
    }

    fn flush(&self) {
        unsafe {
            for value in (*self.cache.get()).values() {
                value.flush();
            }
        }
    }
}
