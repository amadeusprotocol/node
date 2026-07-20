defmodule RPC.API do
  defp http_opts(url) do
    case URI.parse(url) do
      %{scheme: "https", host: host} when is_binary(host) ->
        %{ssl_options: [
          {:server_name_indication, ~c"#{host}"},
          {:verify, :verify_peer},
          {:depth, 99},
          {:cacerts, :certifi.cacerts()},
          {:partial_chain, &Photon.GenTCP.partial_chain/1},
          {:customize_hostname_check, [{:match_fun, :public_key.pkix_verify_hostname_match_fun(:https)}]}
        ]}
      _ ->
        %{}
    end
  end

  # JSON-decoded GET; raises if upstream is not 200. For success-path RPC calls.
  def get(path) do
    url = Application.fetch_env!(:ama, :rpc_url)
    {:ok, %{status_code: 200, body: body}} = :comsat_http.get(url <> path, %{}, http_opts(url))
    JSX.decode!(body, labels: :attempt_atom)
  end

  # Raw GET — returns {:ok, response} for any status code, {:error, _} on
  # transport failure. Body is not decoded. Used by the multiserver proxy
  # so it can forward status + body verbatim without a JSON round-trip.
  def get_raw(path) do
    url = Application.fetch_env!(:ama, :rpc_url)
    case :comsat_http.get(url <> path, %{}, http_opts(url)) do
      {:ok, resp} -> {:ok, resp}
      err -> {:error, err}
    end
  end

  defmodule Wallet do
    def transfer(seed64, receiver, amount_float, symbol \\ "AMA") do
      receiver = if byte_size(receiver) != 48, do: Base58.decode(receiver), else: receiver
      receiver_b58 = Base58.encode(receiver)
      if !BlsEx.validate_public_key(receiver) and receiver != BIC.Coin.burn_address() do
        IO.inspect {"sending #{amount_float} AMA to invalid public key", receiver_b58}
        %{error: :invalid_public_key, pk: receiver_b58}
      else
        txu = API.Wallet.transfer(seed64, receiver, amount_float, symbol, false)
        RPC.API.get("/api/tx/submit_and_wait/#{Base58.encode(txu |> TX.pack())}?finalized=true")
      end
    end

    def transfer_bulk(seed64, receiver_amount_list) do
      Enum.map(receiver_amount_list, fn
        {receiver, amount_float} ->
          receiver = if byte_size(receiver) != 48, do: Base58.decode(receiver), else: receiver
          receiver_b58 = Base58.encode(receiver)
          if !BlsEx.validate_public_key(receiver) and receiver != BIC.Coin.burn_address() do
            IO.inspect {"sending #{trunc(amount_float)} AMA to invalid public key", receiver_b58}
            %{error: :invalid_public_key, pk: receiver_b58}
          else
            IO.inspect {"sending #{trunc(amount_float)} AMA to ", receiver_b58}
            txu = API.Wallet.transfer(seed64, receiver, amount_float, "AMA", false)
            RPC.API.get("/api/tx/submit_and_wait/#{Base58.encode(txu |> TX.pack())}?finalized=true")
          end

        {receiver, amount_float, symbol} ->
          receiver = if byte_size(receiver) != 48, do: Base58.decode(receiver), else: receiver
          receiver_b58 = Base58.encode(receiver)
          if !BlsEx.validate_public_key(receiver) and receiver != BIC.Coin.burn_address() do
            IO.inspect {"sending #{amount_float} AMA to invalid public key", receiver_b58}
            %{error: :invalid_public_key, pk: receiver_b58}
          else
            IO.inspect {"sending #{amount_float} #{symbol} to ", receiver_b58}
            txu = API.Wallet.transfer(seed64, receiver, amount_float, symbol, false)
            RPC.API.get("/api/tx/submit_and_wait/#{Base58.encode(txu |> TX.pack())}?finalized=true")
          end
      end)
    end

    def transfer_bulk_from_text(seed, text) do
      lines = String.split(String.trim(text), "\n")
      |> Enum.filter(& &1 != "")
      Enum.map(lines, fn line->
        [pk, amount] = :binary.split(line, " ")
        {pk, :erlang.binary_to_integer(amount) * 1.0}
      end)
    end

    def balance(pk, symbol \\ "AMA") do
      RPC.API.get("/api/wallet/balance/#{pk}/#{symbol}")
    end
  end

  defmodule Chain do
    def tx(txid) do
      RPC.API.get("/api/chain/tx/#{txid}")
    end
  end

  defmodule Vault do
    defp submit(txu) do
      RPC.API.get("/api/tx/submit_and_wait/#{Base58.encode(txu |> TX.pack())}?finalized=true")
    end

    # opts: :validator, :payout_address, :owner, :unlock_epoch, :months
    def create(seed64, amount, tier \\ "og", opts \\ []) do
      API.Vault.create(seed64, amount, tier, opts, false) |> submit()
    end

    def unlock(seed64, vault_index) do
      API.Vault.unlock(seed64, vault_index, false) |> submit()
    end

    def set_payout_address(seed64, vault_index, payout_pk) do
      API.Vault.set_payout_address(seed64, vault_index, payout_pk, false) |> submit()
    end

    def clear_payout_address(seed64, vault_index) do
      API.Vault.clear_payout_address(seed64, vault_index, false) |> submit()
    end

    def set_validator(seed64, vault_index, validator_pk) do
      API.Vault.set_validator(seed64, vault_index, validator_pk, false) |> submit()
    end

    def clear_validator(seed64, vault_index) do
      API.Vault.clear_validator(seed64, vault_index, false) |> submit()
    end

    def change_owner(seed64, vault_index, new_owner_pk) do
      API.Vault.change_owner(seed64, vault_index, new_owner_pk, false) |> submit()
    end

    def extend_lock(seed64, vault_index, months) do
      API.Vault.extend_lock(seed64, vault_index, months, false) |> submit()
    end

    def set_commission(seed64, bps) do
      API.Vault.set_commission(seed64, bps, false) |> submit()
    end
  end
end
