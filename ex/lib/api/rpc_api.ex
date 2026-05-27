defmodule RPC.API do
  defp http_opts(url) do
    %{ssl_options: [{:server_name_indication, ~c"#{URI.parse(url).host}"}, {:verify, :verify_none}]}
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
end
