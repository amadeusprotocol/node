defmodule RDB do
  @moduledoc false

  use Rustler,
    otp_app: :ama,
    crate: "rdb"

  def open_transaction_db(_path, _cf_names), do: :erlang.nif_error(:nif_not_loaded)
  def close_db(_db), do: :erlang.nif_error(:nif_not_loaded)
  def drop_cf(_db, _cf), do: :erlang.nif_error(:nif_not_loaded)
  def property_value(_db, _key), do: :erlang.nif_error(:nif_not_loaded)
  def property_value_cf(_cf, _key), do: :erlang.nif_error(:nif_not_loaded)
  def compact_range_cf_all(_cf), do: :erlang.nif_error(:nif_not_loaded)
  def checkpoint(_db, _path), do: :erlang.nif_error(:nif_not_loaded)
  def flush_wal(_db), do: :erlang.nif_error(:nif_not_loaded)
  def flush(_db), do: :erlang.nif_error(:nif_not_loaded)
  def flush_cf(_cf), do: :erlang.nif_error(:nif_not_loaded)
  def get(_db, _key), do: :erlang.nif_error(:nif_not_loaded)
  def get_cf(_cf, _key), do: :erlang.nif_error(:nif_not_loaded)
  def exists(_db, _key), do: :erlang.nif_error(:nif_not_loaded)
  def exists_cf(_cf, _key), do: :erlang.nif_error(:nif_not_loaded)
  def put(_db, _key, _value), do: :erlang.nif_error(:nif_not_loaded)
  def put_cf(_cf, _key, _value), do: :erlang.nif_error(:nif_not_loaded)
  def delete(_db, _key), do: :erlang.nif_error(:nif_not_loaded)
  def delete_cf(_cf, _key), do: :erlang.nif_error(:nif_not_loaded)
  def delete_range_cf(_cf, _start_key, _end_key, _compact), do: :erlang.nif_error(:nif_not_loaded)
  def iterator(_db), do: :erlang.nif_error(:nif_not_loaded)
  def iterator_close(_it), do: :erlang.nif_error(:nif_not_loaded)
  def iterator_cf(_cf), do: :erlang.nif_error(:nif_not_loaded)
  def iterator_move(_it, _action), do: :erlang.nif_error(:nif_not_loaded)
  def transaction(_db), do: :erlang.nif_error(:nif_not_loaded)
  def transaction_with_snapshot(_db), do: :erlang.nif_error(:nif_not_loaded)
  def transaction_commit(_tx), do: :erlang.nif_error(:nif_not_loaded)
  def transaction_rollback(_tx), do: :erlang.nif_error(:nif_not_loaded)
  def transaction_set_savepoint(_tx), do: :erlang.nif_error(:nif_not_loaded)
  def transaction_rollback_to_savepoint(_tx), do: :erlang.nif_error(:nif_not_loaded)
  def transaction_get(_tx, _key), do: :erlang.nif_error(:nif_not_loaded)
  def transaction_get_cf(_tx, _cf, _key), do: :erlang.nif_error(:nif_not_loaded)
  def transaction_exists(_tx, _key), do: :erlang.nif_error(:nif_not_loaded)
  def transaction_exists_cf(_tx, _cf, _key), do: :erlang.nif_error(:nif_not_loaded)
  def transaction_put(_tx, _key, _value), do: :erlang.nif_error(:nif_not_loaded)
  def transaction_put_cf(_tx, _cf, _key, _value), do: :erlang.nif_error(:nif_not_loaded)
  def transaction_delete(_tx, _key), do: :erlang.nif_error(:nif_not_loaded)
  def transaction_delete_cf(_tx, _cf, _key), do: :erlang.nif_error(:nif_not_loaded)
  def transaction_scan_cf(_tx, _cf_or_nil, _prefix, _cursor, _direction, _skip_cursor, _offset, _limit, _max_bytes), do: :erlang.nif_error(:nif_not_loaded)

  def apply_entry(_db, _entry, _pk, _sk, _testnet, _testnet_peddlebike), do: :erlang.nif_error(:nif_not_loaded)
  def contract_view(_db, _entry, _view_pk, _contract, _function, _args, _testnet), do: :erlang.nif_error(:nif_not_loaded)
  def contract_validate(_db, _entry, _wasmbytes, _testnet), do: :erlang.nif_error(:nif_not_loaded)

  def vecpak_encode(_map), do: :erlang.nif_error(:nif_not_loaded)
  def vecpak_decode(_bin), do: :erlang.nif_error(:nif_not_loaded)

  def freivalds(_tensor, _vr), do: :erlang.nif_error(:nif_not_loaded)

  def compute_upow(_epoch, _segment_vr_hash, _trainer, _pop, _computor, _diff_bits, _iterations, _threads), do: :erlang.nif_error(:nif_not_loaded)

  def hbsmt_root(_propslist), do: :erlang.nif_error(:nif_not_loaded)
  def hbsmt_root_prove(_propslist, _ns, _key), do: :erlang.nif_error(:nif_not_loaded)
  def hbsmt_root_verify(_expected_root, _proof, _ns, _key, _value), do: :erlang.nif_error(:nif_not_loaded)
  def hbsmt_contractstate_root_prove(_db, _ns, _key), do: :erlang.nif_error(:nif_not_loaded)

  def protocol_constants(), do: :erlang.nif_error(:nif_not_loaded)
  def protocol_epoch_emission(_epoch), do: :erlang.nif_error(:nif_not_loaded)
  def protocol_circulating_without_burn(_epoch), do: :erlang.nif_error(:nif_not_loaded)

  def build_tx_hashfilter(_signer, _arg0, _contract, _function), do: :erlang.nif_error(:nif_not_loaded)
  def build_tx_hashfilters(_txus), do: :erlang.nif_error(:nif_not_loaded)
  def query_tx_hashfilter(_db, _signer, _arg0, _contract, _function, _limit, _sort, _cursor), do: :erlang.nif_error(:nif_not_loaded)
end

defmodule RDBProtocol do
  def reserve_ama_per_tx_exec() do
    const = :persistent_term.get({ProtocolConstant, :reserve_ama_per_tx_exec}, nil)
    if const do const else
      const = RDB.protocol_constants().reserve_ama_per_tx_exec
      :persistent_term.put({ProtocolConstant, :reserve_ama_per_tx_exec}, const)
      const
    end
  end

  def reserve_ama_per_tx_storage() do
    const = :persistent_term.get({ProtocolConstant, :reserve_ama_per_tx_storage}, nil)
    if const do const else
      const = RDB.protocol_constants().reserve_ama_per_tx_storage
      :persistent_term.put({ProtocolConstant, :reserve_ama_per_tx_storage}, const)
      const
    end
  end

  def cost_per_byte_historical() do
    const = :persistent_term.get({ProtocolConstant, :cost_per_byte_historical}, nil)
    if const do const else
      const = RDB.protocol_constants().cost_per_byte_historical
      :persistent_term.put({ProtocolConstant, :cost_per_byte_historical}, const)
      const
    end
  end

  def ama_1_cent() do
    const = :persistent_term.get({ProtocolConstant, :ama_1_cent}, nil)
    if const do const else
      const = RDB.protocol_constants().ama_1_cent
      :persistent_term.put({ProtocolConstant, :ama_1_cent}, const)
      const
    end
  end

  def forkheight() do
    const = :persistent_term.get({ProtocolConstant, :forkheight}, nil)
    if const do const else
      const = RDB.protocol_constants().forkheight
      :persistent_term.put({ProtocolConstant, :forkheight}, const)
      const
    end
  end
end
