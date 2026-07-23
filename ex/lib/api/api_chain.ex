defmodule API.Chain do
    def entry_tip() do
        entry = DB.Chain.tip_entry()
        entry = format_entry_for_client(entry)
        %{error: :ok, entry: entry}
    end

    def entry(entry_hash, filter_on_function \\ nil) do
        entry_hash = if byte_size(entry_hash) != 32, do: Base58.decode(entry_hash), else: entry_hash
        entry = DB.Entry.by_hash(entry_hash)
        if !entry do
            %{error: :not_found}
        else
            next_entry = API.Chain.by_height(entry.header.height+1).entries
            |> Enum.find(& &1.header.prev_hash == Base58.encode(entry.hash) && &1[:consensus][:finality_reached])
            entry = format_entry_for_client(entry)
            entry = if !next_entry do entry else
              put_in(entry, [:next_entry_hash_finality_reached], next_entry.hash)
            end
            entry = if !filter_on_function do entry else
              txs_filtered = API.TX.get_by_entry(entry.hash)
              |> Enum.filter(& TX.action(&1)[:function] == filter_on_function)
              put_in(entry, [:txs_filtered], txs_filtered)
            end
            %{error: :ok, entry: entry}
        end
    end

    def by_height(height) do
        entries = DB.Entry.by_height(height)
        |> Enum.map(& format_entry_for_client(&1))
        %{error: :ok, entries: entries}
    end

    def by_height_with_txs(height) do
        entries = DB.Entry.by_height(height)
        |> Enum.map(fn(entry)->
            txs = API.TX.get_by_entry(entry.hash)
            entry = format_entry_for_client(entry)
            Map.put(entry, :txs, txs)
        end)
        %{error: :ok, entries: entries}
    end

    def consensuses_by_height(height) do
        DB.Attestation.consensuses_by_height(height)
        |> Enum.map(fn(c)->
            aggsig = %{
              aggsig: Base58.encode(c.aggsig.aggsig),
              mask: Base58.encode(c.aggsig.mask),
              mask_size: c.aggsig.mask_size,
              mask_set_size: c.aggsig.mask_set_size,
            }
            c = put_in(c, [:mutations_hash], Base58.encode(c.mutations_hash))
            c = put_in(c, [:entry_hash], Base58.encode(c.entry_hash))
            c = put_in(c, [:aggsig], aggsig)
            c = put_in(c, [:score], length(c.signers) / bit_size(c.mask))
            Map.drop(c, [:mask])
        end)
    end

    def stats(next_entry \\ nil) do
      {tip, epoch} = if next_entry do {next_entry, div(next_entry.header.height, 100_000)} else
        tip = DB.Chain.tip_entry()
        {tip, div(tip.header.height, 100_000)}
      end

      supply = NodeStatsGen.supply()

      %{
        height: tip.header.height,
        rooted_height: DB.Chain.rooted_height(),
        tip_hash: tip.hash |> Base58.encode(),
        tip: format_entry_for_client(tip),
        tx_pool_size: TXPool.size(),
        cur_validator: DB.Chain.validator_for_height_current() |> Base58.encode(),
        next_validator: DB.Chain.validator_for_height_next() |> Base58.encode(),
        emission_for_epoch: BIC.Coin.from_flat(RDB.protocol_epoch_emission(epoch)),
        circulating: (supply && supply.circulating) || BIC.Coin.from_flat(RDB.protocol_circulating_without_burn(epoch)),
        total_supply: supply && supply.total_supply,
        total_locked: supply && supply.total_locked,
        validators: NodeStatsGen.validators(),
        supply_computed_at_height: supply && supply.computed_at_height,
        total_supply_y3: total_supply_y3(),
        total_supply_y30: total_supply_y30(),
        burned: API.Contract.total_burned().float,
        diff_bits: API.Epoch.get_diff_bits(),
        pflops: pflops(tip.header.height),
        txs_per_sec: stat_txs_sec(tip.header.height),
        segment_vr_hash: DB.Chain.segment_vr_hash() |> Base58.encode(),
      }
    end

    def kpi() do
      {_, uaw} = API.Contract.richlist()
      %{
        ama_burned: Float.round(API.Contract.total_burned().float, 2),
        fees_paid: Float.round(API.Contract.total_burned().float * 2, 2),
        active_validator_keys: 67 + length(API.Epoch.score()),
        active_peers: length(API.Peer.all()),
        block_time: 500,
        total_tx: DB.Chain.tx_count(),
        uaw: uaw,
      }
    end

    def total_supply_y3() do
      cached = :persistent_term.get(:total_supply_y3, nil)
      if cached do cached else
        value = BIC.Coin.from_flat(RDB.protocol_circulating_without_burn(500*3))
        :persistent_term.put(:total_supply_y3, value)
        value
      end
      804_065_972
    end

    def total_supply_y30() do
      cached = :persistent_term.get(:total_supply_y30, nil)
      if cached do cached else
        value = BIC.Coin.from_flat(RDB.protocol_circulating_without_burn(500*30))
        :persistent_term.put(:total_supply_y30, value)
        value
      end
      1_000_000_000
    end

    def pflops(height) do
      #A*B=C M=16 K=50240 N=16 u8xi8=i32
      height_in_epoch = rem(height, 100_000)
      total_score = API.Epoch.score() |> Enum.map(& Enum.at(&1,1)) |> Enum.sum()
      diff_multiplier = Bitwise.bsl(1, API.Epoch.get_diff_bits())
      total_calcs = total_score * diff_multiplier
      macs = 16*16*50240
      ops = macs*2

      seconds = height_in_epoch * 0.5 + 1
      ((total_calcs * ops) / seconds) / 1.0e15
    end

    def stat_txs_sec(height) do
      height_start = max(height-100, 0)
      last_100 = Enum.sum_by(height_start..height, fn(height)->
        case DB.Entry.by_height(height) |> List.first() do
          nil -> 0
          entry -> length(entry.txs)
        end
      end)
      last_100/50
    end

    def format_entry_for_client(nil) do nil end
    def format_entry_for_client(entry) do
        hash = entry.hash
        entry = Map.put(entry, :tx_count, length(entry.txs))
        entry = Map.drop(entry, [:signature, :txs])
        {_, entry} = pop_in(entry, [:header, :txs_hash]) #old format; keep for backwards compat
        entry = put_in(entry, [:hash], Base58.encode(entry.hash))
        entry = if !entry[:mask] do entry else
          entry
          |> put_in([:mask], Base58.encode(entry.mask))
          |> put_in([:mask_size], entry.mask_size)
        end
        entry = put_in(entry, [:header, :dr], Base58.encode(entry.header.dr))
        entry = put_in(entry, [:header, :vr], Base58.encode(entry.header.vr))
        entry = put_in(entry, [:header, :prev_hash], Base58.encode(entry.header.prev_hash))
        entry = put_in(entry, [:header, :signer], Base58.encode(entry.header.signer))
        #new additions
        entry = if !entry.header[:root_tx] do entry else put_in(entry, [:header, :root_tx], Base58.encode(entry.header.root_tx)) end
        entry = if !entry.header[:root_validator] do entry else put_in(entry, [:header, :root_validator], Base58.encode(entry.header.root_validator)) end

        entry = put_in(entry, [:header], entry.header)
        {mut_hash, score} = DB.Attestation.best_consensus_by_entryhash(hash)
        if !mut_hash do entry else
            entry = put_in(entry, [:consensus], %{})
            entry = put_in(entry, [:consensus, :score], Float.round(score, 3))
            entry = put_in(entry, [:consensus, :finality_reached], Float.round(score, 3) >= 0.67)
            entry = put_in(entry, [:consensus, :mut_hash], Base58.encode(mut_hash))
            entry
        end
    end
end
