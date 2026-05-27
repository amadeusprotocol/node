defmodule NodeANR do
  @doc """
  AMA Node Record
  """

  @max_anr_size 390
  @shared_secret_cache_ttl_ms 60_000*60
  @keys [:ip4, :pk, :pop, :port, :signature, :ts, :version, :anr_name, :anr_desc]
  @keys_for_signature @keys -- [:signature]

  def keys(), do: @keys

  def seed() do
    Application.fetch_env!(:ama, :seedanrs)
    |> Enum.each(fn(anr)->
      insert(anr)
    end)
    insert(build())
    set_handshaked(Application.fetch_env!(:ama, :trainer_pk))

    Enum.each(handshaked(), fn(%{pk: pk})->
      pk != Application.fetch_env!(:ama, :trainer_pk) && set_last_message(pk)
    end)
  end

  def get_or_build() do
    ts_m = :os.system_time(1000)
    anr = Application.fetch_env!(:ama, :anr)
    if ts_m < Application.fetch_env!(:ama, :anr_next_refresh) do anr else
      anr = build()
      Application.put_env(:ama, :anr, anr)
      Application.put_env(:ama, :anr_next_refresh, ts_m + 60_000*10)
      anr
    end
  end

  def build() do
    sk = Application.fetch_env!(:ama, :trainer_sk)
    pk = Application.fetch_env!(:ama, :trainer_pk)
    pop = Application.fetch_env!(:ama, :trainer_pop)
    ver = Application.fetch_env!(:ama, :version)
    anr_name = Application.fetch_env!(:ama, :anr_name)
    anr_desc = Application.fetch_env!(:ama, :anr_desc)
    build(sk, pk, pop, STUN.get_current_ip4(), ver, anr_name, anr_desc)
  end

  #TODO: Later change this to erlang term
  def build(sk, pk, pop, ip4, ver, anr_name \\ nil, anr_desc \\ nil) do
    anr = %{
      ip4: ip4,
      pk: pk,
      pop: pop,
      port: 36969,
      ts: :os.system_time(1),
      version: ver
    }
    anr = if !anr_name do anr else Map.put(anr, :anr_name, anr_name) end
    anr = if !anr_desc do anr else Map.put(anr, :anr_desc, anr_desc) end
    anr_to_sign = anr |> RDB.vecpak_encode()
    sig = BlsEx.sign!(sk, anr_to_sign, BLS12AggSig.dst_anr())
    anr = Map.put(anr, :signature, sig)
  end

  def delete(pk) do
    MnesiaKV.delete(NODEANR, pk)
    :ets.delete(NODEANRHOT, pk)
    :ets.delete(SharedSecretCache, pk)
  end

  def pack(anr) do
    Map.take(anr, @keys)
  end

  def unpack(anr) do
    if anr.port == 36969 do
      Map.take(anr, @keys)
    end
  end

  def verify_signature(anr) do
    signed = Map.take(anr, @keys_for_signature)
    |> RDB.vecpak_encode()
    BlsEx.verify?(anr.pk, anr.signature, signed, BLS12AggSig.dst_anr())
    and BlsEx.verify?(anr.pk, anr.pop, anr.pk, BLS12AggSig.dst_pop())
  end

  def verify_and_unpack(anr) do
    try do
      # Not wound into future
      ts = :os.system_time(1)
      goodDelta = (ts - anr.ts) > -3600 #60 minutes max into future

      # Parseable IPv4 address
      goodIp4 = valid_ip4?(anr.ip4)

      # Not too big
      bin = RDB.vecpak_encode(anr)
      anr = Map.take(anr, @keys)
      if byte_size(bin) <= @max_anr_size and goodDelta and goodIp4 and verify_signature(anr) do
        anr
      end
    catch
      _,_ -> nil
    end
  end

  def insert_new(anr) do
    :ets.delete(SharedSecretCache, anr.pk)
    anr = Map.put(anr, :handshaked, false)
    anr = Map.put(anr, :error, nil)
    anr = Map.put(anr, :error_tries, 0)
    anr = Map.put(anr, :next_check, :os.system_time(1000)+9_000)
    <<pk_b3_f4::binary-4, _::binary>> = pk_b3 = Blake3.hash(anr.pk)
    anr = Map.put(anr, :pk_b3, pk_b3)
    anr = Map.put(anr, :pk_b3_f4, pk_b3_f4)
    MnesiaKV.merge(NODEANR, anr.pk, anr)
  end

  def routed_peer?(ip4) do
    !Application.fetch_env!(:ama, :check_routed_peer) or CymruRouting.globally_routed?(ip4)
  end

  def valid_ip4?(ip4) do
    is_binary(ip4) and match?({:ok, {_,_,_,_}}, :inet.parse_address(~c'#{ip4}'))
  end

  def insert(anr) do
    if !valid_ip4?(anr[:ip4]) do
      nil
    else
      anr = Map.put(anr, :hasChainPop, !!DB.Chain.pop(anr.pk))
      old_anr = MnesiaKV.get(NODEANR, anr.pk)
      if !routed_peer?(anr.ip4) do
        if !old_anr or old_anr[:ip4] == anr.ip4 or !old_anr[:ts] or anr.ts > old_anr.ts do
          delete(anr.pk)
        end
        nil
      else
        cond do
          !old_anr or !old_anr[:ts] -> insert_new(anr)
          anr.ts <= old_anr.ts -> nil
          old_anr.ip4 == anr.ip4 and old_anr.port == anr.port -> MnesiaKV.merge(NODEANR, anr.pk, anr)
          true -> insert_new(anr)
        end
      end
    end
  end

  def get_shared_secret(pk) do
    now = :os.system_time(1000)
    case :ets.lookup(SharedSecretCache, pk) do
      [{^pk, shared_secret, _last_used}] ->
        if handshaked(pk) do
          :ets.update_element(SharedSecretCache, pk, [{3, now}])
        else
          :ets.delete(SharedSecretCache, pk)
        end
        shared_secret

      [{^pk, shared_secret}] ->
        :ets.delete(SharedSecretCache, pk)
        shared_secret

      _ ->
        shared_secret = BlsEx.get_shared_secret!(pk, Application.fetch_env!(:ama, :trainer_sk))
        if handshaked(pk) do
          :ets.insert(SharedSecretCache, {pk, shared_secret, now})
        end
        shared_secret
    end
  end

  def set_handshaked(pk, flag \\ true) do
    if !flag do
      :ets.delete(SharedSecretCache, pk)
    end
    if MnesiaKV.get(NODEANR, pk) do
      MnesiaKV.merge(NODEANR, pk, %{handshaked: flag})
    end
  end

  def not_handshaked_pk_ip4() do
    :ets.select(:"Elixir.NODEANR_index", [{{{:"$1", false, :"$2", :_}, :_}, [], [%{pk: :"$1", ip4: :"$2"}]}])
  end

  def handshaked_pk_ip4() do
    :ets.select(:"Elixir.NODEANR_index", [{{{:"$1", true, :"$2", :_}, :_}, [], [{{:"$1", :"$2"}}]}])
  end

  def handshaked() do
    :ets.select(:"Elixir.NODEANR_index", [{{{:"$1", true, :"$2", :_}, :_}, [], [%{pk: :"$1", ip4: :"$2"}]}])
  end

  def handshaked(pk) when is_binary(pk) do
    case :ets.select(:"Elixir.NODEANR_index", [{{{pk, true, :_, :_}, :_}, [], [true]}], 1) do
      :"$end_of_table" -> false
      {[true], _} -> true
    end
  end

  def by_pks_ip(pks) when is_list(pks) do
    match_spec = Enum.map(pks, fn(pk)-> {{{pk, true, :"$1", :_}, :_}, [], [:"$1"]} end)
    :ets.select(:"Elixir.NODEANR_index", match_spec)
  end

  def b3_f4() do
    :ets.select(:"Elixir.NODEANR_index", [{{{:_, :_, :_, :_}, %{pk_b3_f4: :"$1"}}, [], [:"$1"]}])
  end

  def by_pks_b3_f4(pks) when is_list(pks) do
    match_spec = Enum.map(pks, fn(pk)-> {{{pk, true, :_, :_}, %{pk_b3_f4: :"$1"}}, [], [:"$1"]} end)
    :ets.select(:"Elixir.NODEANR_index", match_spec)
  end

  def handshaked_and_valid_ip4(pk, ip4) do
    case :ets.select(:"Elixir.NODEANR_index", [{{{pk, true, ip4, :_}, :_}, [], [true]}], 1) do
      :"$end_of_table" -> false
      {[true], _} -> true
    end
  end

  def handshaked_and_online() do
    ts_m = :os.system_time(1000)
    cutoff = ts_m - 30_000

    cur_validator = DB.Chain.validator_for_height_current()
    validators = DB.Chain.validators_for_height(DB.Chain.height()+1)
    {left, rest} = Enum.split_while(validators, &(&1 != cur_validator))
    validators = rest ++ left

    peers = :ets.select(:"Elixir.NODEANR_index", [{{{:"$1", true, :"$2", :_}, :_}, [], [%{pk: :"$1", ip4: :"$2"}]}])
    |> Enum.filter(& NodeANR.get_last_message(&1.pk) >= cutoff)
    validator_peers = Enum.filter(peers, & &1.pk in validators)
    {validator_peers, Enum.shuffle(peers -- validator_peers)}
  end

  def by_pk(pk) do
    MnesiaKV.get(NODEANR, pk)
  end

  def all() do
    MnesiaKV.get(NODEANR)
  end

  def all_validators() do
    validators = DB.Chain.validators_for_height(DB.Chain.height()+1)
    match_spec = Enum.map(validators, fn(pk)-> {{pk, :_}, [], [{:element, 2, :"$_"}]} end)
    :ets.select(NODEANR, match_spec)
  end

  def get_random_verified(cnt \\ 3) do
    handshaked()
    |> Enum.shuffle()
    |> Enum.take(cnt)
    |> Enum.uniq_by(& &1.ip4)
  end

  def get_random_unverified(cnt \\ 1) do
    not_handshaked_pk_ip4()
    |> Enum.shuffle()
    |> Enum.take(cnt)
    |> Enum.uniq_by(& &1.ip4)
  end

  def clear_verified_offline() do
    ts_m = :os.system_time(1000)
    cutoff = ts_m - 30_000
    :ets.select(:"Elixir.NODEANR_index", [{{{:"$1", true, :_, :_}, :_}, [], [:"$1"]}])
    |> Enum.each(fn(pk)->
      if get_last_message(pk) < cutoff do
        set_handshaked(pk, false)
      end
    end)
  end

  def clear_verified_unrouted() do
    my_pk = Application.fetch_env!(:ama, :trainer_pk)
    handshaked()
    |> Enum.reject(& &1.pk == my_pk)
    |> Enum.each(fn %{pk: pk, ip4: ip4}->
      if !routed_peer?(ip4) do
        delete(pk)
      end
    end)
  end

  def prune_shared_secret_cache() do
    cutoff = :os.system_time(1000) - @shared_secret_cache_ttl_ms
    :ets.select_delete(SharedSecretCache, [{{:"$1", :_, :"$2"}, [{:<, :"$2", cutoff}], [true]}])

    :ets.select(SharedSecretCache, [{{:"$1", :_, :_}, [], [:"$1"]}, {{:"$1", :_}, [], [:"$1"]}])
    |> Enum.each(fn pk ->
      if !handshaked(pk) do
        :ets.delete(SharedSecretCache, pk)
      end
    end)
  end

  # ETS schema: {pk, last_message, version, latency, rooted, temporal, pruned_below_height}
  # `pruned_below_height` (slot 7) is the lowest height the peer can still
  # serve — 0 means full history. peers_w_min_height/2 filters by this.
  def set_last_message(pk) do
    ts_m = :os.system_time(1000)
    :ets.update_element(NODEANRHOT, pk, [{2, ts_m}], {pk, ts_m, "", 0, %{}, %{}, 0})
  end

  def set_version(pk, version) do
    ts_m = :os.system_time(1000)
    :ets.update_element(NODEANRHOT, pk, [{2, ts_m}, {3, version}], {pk, ts_m, version, 0, %{}, %{}, 0})
  end

  def set_version_latency(pk, version, latency) do
    ts_m = :os.system_time(1000)
    :ets.update_element(NODEANRHOT, pk, [{2, ts_m}, {3, version}, {4, latency}], {pk, ts_m, version, latency, %{}, %{}, 0})
  end

  def set_tips(pk, rooted, temporal, pruned_below \\ 0) do
    ts_m = :os.system_time(1000)
    if !rooted do
      :ets.update_element(NODEANRHOT, pk, [{2, ts_m}, {6, temporal}, {7, pruned_below}], {pk, ts_m, "", 0, %{}, %{}, 0})
    else
      :ets.update_element(NODEANRHOT, pk, [{2, ts_m}, {5, rooted}, {6, temporal}, {7, pruned_below}], {pk, ts_m, "", 0, %{}, %{}, 0})
    end
  end

  def get_last_message(pk) do :ets.lookup_element(NODEANRHOT, pk, 2, 0) end
  def get_version(pk) do :ets.lookup_element(NODEANRHOT, pk, 3, "") end
  def get_latency(pk) do :ets.lookup_element(NODEANRHOT, pk, 4, 0) end
  def get_pruned_below_height(pk) do :ets.lookup_element(NODEANRHOT, pk, 7, 0) end
  def get_peer_hotdata(pk) do
    case :ets.lookup(NODEANRHOT, pk) do
      [] -> nil
      [{_pk, last_message, version, latency, rooted, temporal, pruned_below}] ->
        %{
          pk: pk,
          last_message: last_message,
          version: version,
          latency: latency,
          rooted: rooted,
          temporal: temporal,
          pruned_below_height: pruned_below
        }
    end
  end

  def get_is_online(pk) do
    (:os.system_time(1000) - get_last_message(pk)) < 30_000
  end

  def min_reached_by_pct(_, pct \\ 0.67)
  def min_reached_by_pct([], pct) do 0 end
  def min_reached_by_pct(peers, pct) do
      n = length(peers)
      k = :math.ceil(pct * n) |> trunc()

      peers
      |> Enum.frequencies_by(& &1.height_root)
      |> Enum.sort_by(fn {h, _} -> h end, :desc)
      |> Enum.reduce_while(0, fn {h, cnt}, acc ->
        acc = acc + cnt
        if acc >= k, do: {:halt, h}, else: {:cont, acc}
      end)
  end

  def highest_validator_height() do
    {vals, peers} = NodeANR.handshaked_and_online()
    vals = Enum.map(vals, fn(%{ip4: ip4, pk: pk})->
      height_root = :ets.lookup_element(NODEANRHOT, pk, 5, nil)[:header][:height]
      height_temp = :ets.lookup_element(NODEANRHOT, pk, 6, nil)[:header][:height]
      %{pk: pk, ip4: ip4, height_root: height_root, height_temp: height_temp}
    end)
    |> Enum.filter(& &1.height_root && &1.height_temp)
    peers = Enum.map(peers, fn(%{ip4: ip4, pk: pk})->
      height_root = :ets.lookup_element(NODEANRHOT, pk, 5, nil)[:header][:height]
      height_temp = :ets.lookup_element(NODEANRHOT, pk, 6, nil)[:header][:height]
      %{pk: pk, ip4: ip4, height_root: height_root, height_temp: height_temp}
    end)
    |> Enum.filter(& &1.height_root && &1.height_temp)
    total = vals ++ peers

    max_height_rooted = total
    |> Enum.sort_by(& &1.height_root, :desc)
    |> List.first()
    |> case do nil -> 0; m -> m.height_root end
    max_height_temp = total
    |> Enum.sort_by(& &1.height_temp, :desc)
    |> List.first()
    |> case do nil -> 0; m -> m.height_temp end
    {max_height_rooted, max_height_temp, min_reached_by_pct(vals)}
  end

  def peers_w_min_height(height, type \\ :any) do
    {vals, peers} = NodeANR.handshaked_and_online()
    total = if type == :any do vals ++ peers else vals end
    total = Enum.map(total, fn(%{ip4: ip4, pk: pk})->
      height_root = :ets.lookup_element(NODEANRHOT, pk, 5, nil)[:header][:height] || 0
      height_temp = :ets.lookup_element(NODEANRHOT, pk, 6, nil)[:header][:height] || 0
      pruned_below = :ets.lookup_element(NODEANRHOT, pk, 7, 0)
      %{pk: pk, ip4: ip4, height_root: height_root, height_temp: height_temp, pruned_below: pruned_below}
    end)
    # Peer must have the requested height in its retained window:
    # (tip ≥ height) AND (pruned floor ≤ height).
    {
      Enum.filter(total, & &1.height_root >= height and &1.pruned_below <= height),
      Enum.filter(total, & &1.height_temp >= height and &1.pruned_below <= height)
    }
  end
end
