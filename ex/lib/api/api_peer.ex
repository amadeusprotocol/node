defmodule API.Peer do
    def trainers(height \\ nil) do
        height = height || DB.Chain.height()+1
        trainerForSlot = DB.Chain.validator_for_height(height)

        DB.Chain.validators_for_height(height)
        |> Enum.map(fn(pk)->
            p = NodeANR.get_peer_hotdata(pk)
            inSlot = trainerForSlot == pk
            if !!p and NodeANR.get_is_online(pk) do
                [Base58.encode(pk), p.version, true, inSlot, p.latency, Base58.encode(get_in(p, [:temporal, :hash])), get_in(p, [:temporal, :header, :height]), get_in(p, [:rooted, :header, :height])]
            else
                [Base58.encode(pk), p[:version], false, inSlot]
            end
        end)
        |> Enum.sort_by(& Enum.at(&1,1), :desc)
    end

    def version_ratio() do
        trainers = trainers()
        trainers
        |> Enum.reduce(%{}, fn([_pk, version | _], acc)->
            Map.put(acc, version, Map.get(acc, version, 0) + 1)
        end)
        |> Enum.sort_by(& elem(&1, 1), :desc)
        |> Enum.map(fn({version, cnt})->
            {version, cnt, Float.round(cnt/length(trainers), 3)}
        end)
    end

    def version_ratio_all() do
        all = all()
        all
        |> Enum.reduce(%{}, fn([version | _], acc)->
            Map.put(acc, version, Map.get(acc, version, 0) + 1)
        end)
        |> Enum.sort_by(& elem(&1, 1), :desc)
        |> Enum.map(fn({version, cnt})->
            {version, cnt, Float.round(cnt/length(all), 3)}
        end)
    end

    def all() do
        {vals, peers} = NodeANR.handshaked_and_online()
        (vals ++ peers)
        |> Enum.map(fn(%{pk: pk})->
          peer = NodeANR.get_peer_hotdata(pk)
          [
            peer[:version],peer[:latency],Base58.encode(pk),
            get_in(peer, [:temporal, :header, :height]),
            get_in(peer, [:rooted, :header, :height]),
          ]
        end)
        |> Enum.sort(:desc)
    end

    def version_ratio_score_by_target(target_ver) do
      version_ratio() |> Enum.filter(& elem(&1,0) >= target_ver) |> Enum.sum_by(& elem(&1,1))
    end

    def all_for_web() do
        {vals, peers} = NodeANR.handshaked_and_online()
        vals = Enum.map(vals, & Map.put(&1, :is_trainer, true))
        (vals ++ peers)
        |> Enum.map(fn(pd=%{pk: pk, ip4: ip4})->
          peer = NodeANR.get_peer_hotdata(pk)
          if peer do
            %{
              pk: Base58.encode(pk),
              version: peer.version,
              latency: peer.latency,
              temporal_height: get_in(peer, [:temporal, :header, :height]),
              temporal_hash: get_in(peer, [:temporal, :hash]) |> Base58.encode(),
              rooted_height: get_in(peer, [:rooted, :header, :height]),
              rooted_hash: get_in(peer, [:rooted, :hash]) |> Base58.encode(),
              is_trainer: pd[:is_trainer]
            }
          end
        end)
        |> Enum.filter(& &1)
        |> Enum.sort_by(& &1.temporal_height, :desc)
    end

    def all_trainers() do
        all_for_web()
        |> Enum.filter(& &1[:is_trainer])
        |> Enum.map(fn(map)->
            Map.put(map, :slot_speed, SpecialMeetingAttestGen.calcSlow(Base58.decode(map.pk)))
        end)
    end

    def removed_trainers(epoch \\ nil) do
        epoch = if !epoch do DB.Chain.epoch() else epoch end
        trainers_for_epoch = DB.Chain.validators_for_height(epoch*100_000)
        trainers = DB.Chain.validators_for_height(DB.Chain.height()+1)
        (trainers_for_epoch -- trainers)
        |> Enum.map(& Base58.encode(&1))
    end

    def anr_all_validators() do
      NodeANR.all_validators()
      |> anr_for_web()
    end

    #TODO: paginate?
    def anr_all() do
      Enum.shuffle(NodeANR.all())
      |> Enum.take(100)
      |> anr_for_web()
    end

    def anr_by_pk(pk) do
      pk = if byte_size(pk) != 48, do: Base58.decode(pk), else: pk
      NodeANR.by_pk(pk)
      |> anr_for_web()
    end

    def anr_for_web(anrs) when is_list(anrs) do Enum.map(anrs, & anr_for_web(&1)) |> Enum.filter(& &1) end
    def anr_for_web(nil) do nil end
    def anr_for_web(anr) do
      %{
        pk: Base58.encode(anr.pk),
        pop: Base58.encode(anr.pop),
        signature: Base58.encode(anr.signature),
        ip4: anr.ip4,
        port: anr.port,
        handshaked: anr.handshaked,
        isChainPop: !!anr[:isChainPop],
        version: anr.version,
        ts: anr.ts,
        anr_name: anr[:anr_name],
        anr_desc: anr[:anr_desc],
      }
    end
end
