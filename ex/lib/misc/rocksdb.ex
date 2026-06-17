defmodule RocksDB do
    def get(key, opts) do
        db = opts[:db]
        cf = opts[:cf]
        rtx = opts[:rtx]
        cond do
            !!rtx and !!cf -> RDB.transaction_get_cf(rtx, cf, key)
            !!rtx -> RDB.transaction_get(rtx, key)
            !!db and !!cf -> RDB.get_cf(cf, key)
            !!db -> RDB.get(db, key)
        end
        |> case do
            {:ok, nil} -> nil
            {:ok, value} ->
                cond do
                    opts[:term] -> :erlang.binary_to_term(value, [:safe])
                    opts[:to_integer] -> :erlang.binary_to_integer(value)
                    true -> value
                end
        end
    end

    def exists(key, opts) do
        db = opts[:db]
        cf = opts[:cf]
        rtx = opts[:rtx]
        cond do
            !!rtx and !!cf -> RDB.transaction_exists_cf(rtx, cf, key)
            !!rtx -> RDB.transaction_exists(rtx, key)
            !!db and !!cf -> RDB.exists_cf(cf, key)
            !!db -> RDB.exists(db, key)
        end
        |> case do
            {:ok, true} -> true
            {:ok, false} -> false
        end
    end

    def get_next(prefix, key, opts = %{rtx: rtx}) when not is_nil(rtx) do
        {_, rows} = RDB.transaction_scan_cf(rtx, tx_scan_cf(opts), prefix, key, :forward, true, tx_scan_offset(opts), 1, opts[:max_bytes] || 0)
        case rows do
            [{next_key, value}] ->
                value = if opts[:term] do :erlang.binary_to_term(value, [:safe]) else value end
                {next_key, value}
            _ -> {nil, nil}
        end
    end
    def get_next(prefix, key, opts) do
        {:ok, it} = iterator(opts)

        seek_string = prefix <> key
        seek_res = RDB.iterator_move(it, {:seek, seek_string})
        seek_res = case seek_res do
            {:ok, ^seek_string, _value} -> RDB.iterator_move(it, :next)
            other -> other
        end

        offset = opts[:offset] || 0
        seek_res = if offset <= 0 do seek_res else
            Enum.reduce(1..offset, seek_res, fn(_, _)->
                RDB.iterator_move(it, :next)
            end)
        end

        RDB.iterator_close(it)
        case seek_res do
            {:ok, <<^prefix::binary, next_key::binary>>, value} ->
                value = if opts[:term] do :erlang.binary_to_term(value, [:safe]) else value end
                {next_key, value}
            _ -> {nil, nil}
        end
    end

    def get_prev(prefix, key, opts = %{rtx: rtx}) when not is_nil(rtx) do
        {_, rows} = RDB.transaction_scan_cf(rtx, tx_scan_cf(opts), prefix, key, :reverse, true, tx_scan_offset(opts), 1, opts[:max_bytes] || 0)
        case rows do
            [{prev_key, value}] ->
                value = if opts[:term] do :erlang.binary_to_term(value, [:safe]) else value end
                {prev_key, value}
            _ -> {nil, nil}
        end
    end
    def get_prev(prefix, key, opts) do
        {:ok, it} = iterator(opts)

        seek_string = prefix <> key
        seek_res = RDB.iterator_move(it, {:seek_for_prev, "#{prefix}#{key}"})
        seek_res = case seek_res do
            {:ok, ^seek_string, _value} -> RDB.iterator_move(it, :prev)
            other -> other
        end

        offset = opts[:offset] || 0
        seek_res = if offset <= 0 do seek_res else
            Enum.reduce(1..offset, seek_res, fn(_, _)->
                RDB.iterator_move(it, :prev)
            end)
        end

        RDB.iterator_close(it)
        case seek_res do
            {:ok, <<^prefix::binary, prev_key::binary>>, value} ->
                value = if opts[:term] do :erlang.binary_to_term(value, [:safe]) else value end
                {prev_key, value}
            _ -> {nil, nil}
        end
    end

    def get_prev_or_first(prefix, key, opts = %{rtx: rtx}) when not is_nil(rtx) do
        {_, rows} = RDB.transaction_scan_cf(rtx, tx_scan_cf(opts), prefix, key, :reverse, false, 0, 1, opts[:max_bytes] || 0)
        case rows do
            [{prev_key, value}] ->
                value = if opts[:term] do :erlang.binary_to_term(value, [:safe]) else value end
                {prev_key, value}
            _ -> {nil, nil}
        end
    end
    def get_prev_or_first(prefix, key, opts) do
        {:ok, it} = iterator(opts)
        res = RDB.iterator_move(it, {:seek_for_prev, "#{prefix}#{key}"})
        RDB.iterator_close(it)
        case res do
            {:ok, <<^prefix::binary, prev_key::binary>>, value} ->
                value = if opts[:term] do :erlang.binary_to_term(value, [:safe]) else value end
                {prev_key, value}
            _ -> {nil, nil}
        end
    end

    def get_bit(key, bit_idx, opts) do
      db = opts[:db]
      cf = opts[:cf]
      rtx = opts[:rtx]
      cond do
          !!rtx and !!cf -> RDB.transaction_get_cf(rtx, cf, key)
          !!rtx -> RDB.transaction_get(rtx, key)
          !!db and !!cf -> RDB.get_cf(cf, key)
          !!db -> RDB.get(db, key)
      end
      |> case do
          {:ok, nil} -> nil
          {:ok, value} ->
            <<_left::size(bit_idx), bit::size(1), _::bitstring >> = value
            bit
      end
    end

    def put(key, value, opts) do
        db = opts[:db]
        cf = opts[:cf]
        rtx = opts[:rtx]
        value = if opts[:term] do :erlang.term_to_binary(value, [:deterministic]) else value end
        value = if opts[:to_integer] do :erlang.integer_to_binary(value) else value end
        cond do
            !!rtx and !!cf -> :ok = RDB.transaction_put_cf(rtx, cf, key, value)
            !!rtx -> :ok = RDB.transaction_put(rtx, key, value)
            !!db and !!cf -> RDB.put_cf(cf, key, value)
            !!db -> RDB.put(db, key, value)
        end
    end

    def delete(key, opts) do
        db = opts[:db]
        cf = opts[:cf]
        rtx = opts[:rtx]
        cond do
            !!rtx and !!cf -> RDB.transaction_delete_cf(rtx, cf, key)
            !!rtx -> RDB.transaction_delete(rtx, key)
            !!db and !!cf -> RDB.delete_cf(cf, key)
            !!db -> RDB.delete(db, key)
        end
    end

    def get_prefix(prefix, opts = %{rtx: rtx}) when not is_nil(rtx) do
        tx_scan_all(rtx, tx_scan_cf(opts), prefix, opts)
        |> Enum.map(fn {key, value} ->
            value = if opts[:term] do :erlang.binary_to_term(value, [:safe]) else value end
            value = if opts[:to_integer] do :erlang.binary_to_integer(value) else value end
            {key, value}
        end)
    end
    def get_prefix(prefix, opts) do
        {:ok, it} = iterator(opts)
        res = RDB.iterator_move(it, {:seek, prefix})
        result = get_prefix_1(prefix, it, res, opts, [])
        RDB.iterator_close(it)
        result
    end
    defp get_prefix_1(prefix, it, res, opts, acc) do
        case res do
            {:ok, <<^prefix::binary, key::binary>>, value} ->
                value = if opts[:term] do :erlang.binary_to_term(value, [:safe]) else value end
                value = if opts[:to_integer] do :erlang.binary_to_integer(value) else value end
                res = RDB.iterator_move(it, :next)
                get_prefix_1(prefix, it, res, opts, acc ++ [{key, value}])
            {:error, :invalid_iterator} -> acc
            _ -> acc
        end
    end

    def delete_prefix(prefix, opts = %{rtx: rtx}) when not is_nil(rtx) do
        tx_delete_prefix(rtx, tx_scan_cf(opts), prefix, opts)
    end
    def delete_prefix(prefix, opts) do
        {:ok, it} = iterator(opts)
        res = RDB.iterator_move(it, {:seek, prefix})
        result = delete_prefix_1(prefix, it, res, opts)
        RDB.iterator_close(it)
        result
    end
    defp delete_prefix_1(prefix, it, res, opts) do
        case res do
            {:ok, <<^prefix::binary, key::binary>>, _value} ->
                res = RDB.iterator_move(it, :next)
                RocksDB.delete(prefix <> key, opts)
                delete_prefix_1(prefix, it, res, opts)
            {:error, :invalid_iterator} -> :ok
            _ -> :ok
        end
    end

    def delete_range_cf_call(cf_atom, compact) do
      %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
      delete_range_cf("", :binary.copy(<<0xFF>>,1024), compact, %{db: db, cf: cf[cf_atom]})
    end

    def delete_range_cf(start_key, end_key, compact, opts) do
      db = opts[:db]
      cf = opts[:cf]
      rtx = opts[:rtx]
      cond do
        #!!rtx and !!cf -> RDB.transaction_delete_cf(rtx, cf, key)
        #!!rtx -> RDB.transaction_delete(rtx, key)
        !!db and !!cf -> RDB.delete_range_cf(cf, start_key, end_key, compact)
        #!!db -> RDB.delete(db, key)
      end
    end

    defp iterator(opts) do
        db = opts[:db]
        cf = opts[:cf]
        cond do
            !!db and !!cf -> RDB.iterator_cf(cf)
            !!db -> RDB.iterator(db)
        end
    end

    def seek_next(key, opts = %{rtx: rtx}) when not is_nil(rtx) do
        {_, rows} = RDB.transaction_scan_cf(rtx, tx_scan_cf(opts), "", key, :forward, false, 0, 1, opts[:max_bytes] || 0)
        case rows do
            [{next_key, value}] -> {next_key, value}
            _ -> {nil, nil}
        end
    end
    def seek_next(key, opts) do
        {:ok, it} = iterator(opts)

        seek_res = RDB.iterator_move(it, {:seek, key})
        RDB.iterator_close(it)
        seek_res = case seek_res do
            {:ok, next_key, value} -> {next_key, value}
            other -> {nil, nil}
        end
    end

    defp tx_scan_cf(%{cf: cf}) when not is_nil(cf), do: cf
    defp tx_scan_cf(_opts), do: nil

    defp tx_scan_offset(opts) do
        max(opts[:offset] || 0, 0)
    end

    defp tx_scan_all(rtx, cf, prefix, opts) do
        tx_scan_all_1(rtx, cf, prefix, "", false, opts[:scan_limit] || 1024, opts[:max_bytes] || 0, [])
    end
    defp tx_scan_all_1(rtx, cf, prefix, cursor, skip_cursor, limit, max_bytes, acc) do
        {next_cursor, rows} = RDB.transaction_scan_cf(rtx, cf, prefix, cursor, :forward, skip_cursor, 0, limit, max_bytes)
        case rows do
            [] -> Enum.reverse(acc)
            _ ->
                acc = Enum.reduce(rows, acc, fn row, acc -> [row | acc] end)
                if max_bytes == 0 and length(rows) < limit do
                    Enum.reverse(acc)
                else
                    tx_scan_all_1(rtx, cf, prefix, next_cursor, true, limit, max_bytes, acc)
                end
        end
    end

    defp tx_delete_prefix(rtx, cf, prefix, opts) do
        tx_delete_prefix_1(rtx, cf, prefix, "", false, opts[:scan_limit] || 1024, opts[:max_bytes] || 0)
    end
    defp tx_delete_prefix_1(rtx, cf, prefix, cursor, skip_cursor, limit, max_bytes) do
        {next_cursor, rows} = RDB.transaction_scan_cf(rtx, cf, prefix, cursor, :forward, skip_cursor, 0, limit, max_bytes)
        case rows do
            [] -> :ok
            _ ->
                Enum.each(rows, fn {key, _value} ->
                    tx_delete_key(rtx, cf, prefix <> key)
                end)
                tx_delete_prefix_1(rtx, cf, prefix, next_cursor, true, limit, max_bytes)
        end
    end

    defp tx_delete_key(rtx, nil, key), do: :ok = RDB.transaction_delete(rtx, key)
    defp tx_delete_key(rtx, cf, key), do: :ok = RDB.transaction_delete_cf(rtx, cf, key)

    def transaction(db) do
      {:ok, rtx} = RDB.transaction(db)
      rtx
    end

    def transaction_commit(rtx) do
      :ok = RDB.transaction_commit(rtx)
    end

    def transaction_rollback(rtx) do
      :ok = RDB.transaction_rollback(rtx)
    end

    def dumpstate() do
      %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
      d = RocksDB.dump(cf.contractstate)
      dd = inspect d, limit: 1111111111111111111, pretty: true
      File.write! "/tmp/amastate", dd
      d = RocksDB.dump(cf.contractstate_tree_hbsmt)
      dd = inspect d, limit: 1111111111111111111, pretty: true
      File.write! "/tmp/amastate_tree", dd
    end

    def dump(cf) do
        {:ok, it} = RDB.iterator_cf(cf)
        res = RDB.iterator_move(it, :first)
        result = dump_1(it, res, [])
        RDB.iterator_close(it)
        result
    end
    defp dump_1(it, res, acc) do
        case res do
            {:ok, key, value} ->
                res = RDB.iterator_move(it, :next)
                dump_1(it, res, acc ++ [{ascii_dump(key), ascii_dump(value)}])
            {:error, :invalid_iterator} -> acc
            _ -> acc
        end
    end

    def ascii_dump(string) do
        for <<c <- string>>, into: "" do
            if c == 32
            or c in 123..126
            or c in ?!..?@
            or c in ?[..?_
            or c in ?0..?9
            or c in ?A..?Z
            or c in ?a..?z do <<c>> else
              <<"?">>
            end
        end
    end

    def checkpoint(db_ref, path) do
        RDB.checkpoint(db_ref, path)
    end

    def snapshot(output_path) do
        %{args: args} = :persistent_term.get({:flatkv_fd, Fabric})
        File.mkdir_p!(output_path)
        {"", 0} = System.shell("cp --reflink=always #{args.path}/#{Fabric} #{output_path}", [{:stderr_to_stdout, true}])
    end

    def restore_from_snapshot(path) do
    end

    def flush_all(cfs) do
        Enum.each(Map.values(cfs), fn(cf)->
            RDB.flush_cf(cf)
        end)
    end

    def flush_wal(db) do
        RDB.flush_wal(db)
    end

    def compact_all(cfs) do
        Enum.each(Map.values(cfs), fn(cf)->
            RDB.compact_range_cf_all(cf)
        end)
    end

    def get_lru(db) do
      {:ok, cap} = :rocksdb.get_property(db, "rocksdb.block-cache-capacity")
      {:ok, used} = :rocksdb.get_property(db, "rocksdb.block-cache-usage")
      {:erlang.binary_to_integer(used), :erlang.binary_to_integer(cap)}
    end

    def get_cf_prop(cf_atom, prop \\ "rocksdb.stats") do
      %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
      case RDB.property_value_cf(cf[cf_atom], prop) do
        {:ok, result} -> result
        _ -> nil
      end
    end

    def get_cf_size(cf_atom) do
      %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
      case RDB.property_value_cf(cf[cf_atom], "rocksdb.total-sst-files-size") do
        {:ok, size_str} ->
          bytes = String.to_integer(size_str)
          bytes / (1024 * 1024 * 1024)
        _ -> nil
      end
    end
end
