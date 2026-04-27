defmodule TX do
   _ = """
   %{
     tx: %{
      signer: Base58PK,
      nonce: :os.system_time(:nanosecond),
      actions: [%{op: "call", contract: "", function: "", args: []}]
     },
     tx_encoded: <<>>,
     hash: <<>>,
     signature: <<>>
   }
   tx = TX.build(Application.fetch_env!(:ama, :trainer_sk), "Coin", "transfer", [])
   {tx1,_} = VanillaSer.decode(tx)
   tx2 = RDB.vecpak_decode(tx)
   VanillaSer.decode(tx1["tx_encoded"])
   VanillaSer.decode(tx2.tx_encoded)
   RDB.vecpak_decode(tx1["tx_encoded"])
   RDB.vecpak_decode(tx2.tx_encoded)

   VanillaSer.encode(VanillaSer.decode(tx1["tx_encoded"]) |> elem(0)) |> RDB.vecpak_decode()
   RDB.vecpak_encode(tx2.tx_encoded) |> RDB.vecpak_decode()

   <<5, 1, 2, 111, 112>>
   <<5, 1, 4, 97, 114, 103, 115>>
   <<5, 1, 8, 99, 111, 110, 116, 114, 97, 99, 116>>
   <<5, 1, 8, 102, 117, 110, 99, 116, 105, 111, 110>>
   <<5, 1, 5, 110, 111, 110, 99, 101>>
   <<5, 1, 6, 115, 105, 103, 110, 101, 114>>
   <<5, 1, 7, 97, 99, 116, 105, 111, 110, 115>>

   """

   @fields [:tx, :hash, :signature]
   @fields_tx [:action, :signer, :nonce]
   @fields_action [:op, :contract, :function, :args, :attached_symbol, :attached_amount]

   def pack(txu) do
     txu = Map.take(txu, @fields)
     RDB.vecpak_encode(txu)
   end

   def unpack(tx_packed) when is_map(tx_packed) do Map.take(tx_packed, @fields) end
   def unpack(tx_packed) do
     try do
      txu = RDB.vecpak_decode(tx_packed)
      txu = if !txu[:tx_encoded] do txu else
        Map.put(txu, :tx, VanillaSer.decode!(txu.tx_encoded))
      end
      Map.take(txu, @fields)
     catch
     _,_ ->
        txu = VanillaSer.decode!(tx_packed)
        tx = VanillaSer.decode!(Map.fetch!(txu, :tx_encoded))
        txu = Map.put(txu, :tx, tx)
     end
   end

   def validate(txu_orig, is_special_meeting_block \\ false) do
    try do
      txu = Map.take(txu_orig, @fields)
      true = txu == txu_orig
      tx = Map.take(txu.tx, @fields_tx)
      true = txu.tx == tx
      txu = put_in(txu, [:tx], tx)
      action = Map.take(txu.tx.action, @fields_action)
      true = txu.tx.action == action
      txu = put_in(txu, [:tx, :action], action)

      tx_encoded = RDB.vecpak_encode(txu.tx)
      if byte_size(tx_encoded) >= Application.fetch_env!(:ama, :tx_size), do: throw(%{error: :too_large})
      if txu.hash != :crypto.hash(:sha256, tx_encoded), do: throw(%{error: :invalid_hash})
      if !BlsEx.verify?(txu.tx.signer, txu.signature, txu.hash, BLS12AggSig.dst_tx()), do: throw(%{error: :invalid_signature})

      #if !!txu.tx[:genesis_hash] and !is_integer(txu.tx.chain_id), do: throw(%{error: :chain_id_not_integer})
      if !is_integer(txu.tx.nonce), do: throw(%{error: :nonce_not_integer})
      if txu.tx.nonce < 0, do: throw(%{error: :nonce_negative})
      if txu.tx.nonce > 18_446_744_073_709_551_615, do: throw(%{error: :nonce_too_high})
      if !is_map(action), do: throw(%{error: :action_must_be_map})
      if action[:op] != "call", do: throw %{error: :op_must_be_call}
      if !is_binary(action[:contract]), do: throw %{error: :contract_must_be_binary}
      if !is_binary(action[:function]), do: throw %{error: :function_must_be_binary}
      if !is_list(action[:args]), do: throw %{error: :args_must_be_list}
      if length(action.args) > 16, do: throw %{error: :args_length_cannot_exceed_16}
      Enum.each(action.args, fn(arg)->
        if !is_binary(arg), do: throw(%{error: :arg_must_be_binary})
      end)

      if is_special_meeting_block do
         if !:lists.member(action.contract, ["Epoch"]), do: throw %{error: :invalid_module_for_special_meeting}
         if !:lists.member(action.function, ["slash_trainer"]), do: throw %{error: :invalid_function_for_special_meeting}
      end

      #attachment
      if !!action[:attached_symbol] and !is_binary(action.attached_symbol), do: throw %{error: :attached_symbol_must_be_binary}
      if !!action[:attached_symbol] and (byte_size(action.attached_symbol) < 1 or byte_size(action.attached_symbol) > 32),
        do: throw %{error: :attached_symbol_wrong_size}

      if !!action[:attached_amount] and !is_binary(action.attached_amount), do: throw %{error: :attached_amount_must_be_binary}

      if !!action[:attached_symbol] and !action[:attached_amount], do: throw %{error: :attached_amount_must_be_included}
      if !!action[:attached_amount] and !action[:attached_symbol], do: throw %{error: :attached_symbol_must_be_included}

      #if !!txp.tx[:delay] and !is_integer(txp.tx.delay), do: throw %{error: :delay_not_integer}
      #if !!txp.tx[:delay] and txp.tx.delay <= 0, do: throw %{error: :delay_too_low}
      #if !!txp.tx[:delay] and txp.tx.delay > 100_000, do: throw %{error: :delay_too_hi}

      throw %{error: :ok, txu: txu}
    catch
        :throw,r -> r
        e,r ->
          IO.inspect {TX, :validate, e, r}
          %{error: :unknown, txu: nil}
    end
   end

   def build(sk, contract, function, args, nonce \\ nil, attached_symbol \\ nil, attached_amount \\ nil) do
     pk = BlsEx.get_public_key!(sk)
     nonce = if !nonce do :os.system_time(:nanosecond) else nonce end
     action = %{op: "call", contract: contract, function: function, args: args}
     action = if is_binary(attached_symbol) and is_binary(attached_amount) do
        Map.merge(action, %{attached_symbol: attached_symbol, attached_amount: attached_amount})
     else action end
     tx = %{
        signer: pk,
        nonce: nonce,
        action: action
     }
     tx_encoded = tx |> RDB.vecpak_encode()
     hash = :crypto.hash(:sha256, tx_encoded)
     signature = BlsEx.sign!(sk, hash, BLS12AggSig.dst_tx())
     %{tx: tx, hash: hash, signature: signature}
   end

   def valid_pk(pk) do
      pk == BIC.Coin.burn_address() or BlsEx.validate_public_key(pk)
   end

   def known_receivers(txu) do
      action = action(txu)
      c = action.contract
      f = action.function
      a = action.args
      case {c,f,a} do
         {"Coin", "transfer", [receiver, _amount, _symbol]} -> valid_pk(receiver) && [receiver]
         {"Epoch", "slash_trainer", [malicious_pk, _epoch, _signature, _mask_size, _mask]} when byte_size(malicious_pk) == 48 -> valid_pk(malicious_pk) && [malicious_pk]
         _ -> nil
      end || []
   end

   def exec_cost(epoch, txu) do
      bytes = byte_size(RDB.vecpak_encode(txu.tx)) + 32 + 96
      BIC.Coin.to_cents( 1 + div(bytes, 1024) * 1 )
   end

   def historical_cost(height, txu) do
      max(
        RDBProtocol.ama_1_cent(),
        RDBProtocol.cost_per_byte_historical() * byte_size(RDB.vecpak_encode(txu.tx)))
   end

   def action(%{tx: %{actions: [action|_]}}), do: action
   def action(%{tx: %{action: action}}), do: action
end
