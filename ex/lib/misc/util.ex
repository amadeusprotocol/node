defmodule Util do
    def hexdump(binary) when is_binary(binary) do
        :binary.bin_to_list(binary)
        |> Enum.chunk_every(16, 16, [])
        |> Enum.with_index()
        |> Enum.map(fn {chunk, index} ->
            # Calculate the offset in bytes
            address = index * 16

            # Convert offset to hex, zero-padded to 8 characters
            offset_str = address
            |> Integer.to_string(16)
            |> String.upcase()
            |> String.pad_leading(8, "0")

            # Convert each byte in the chunk to 2-digit hex (upper-case)
            hex_bytes = chunk
            |> Enum.map(fn byte ->
                byte
                |> Integer.to_string(16)
                |> String.upcase()
                |> String.pad_leading(2, "0")
            end)
            |> Enum.join(" ")

            # Pad the hex field so the ASCII section is always aligned
            # Each byte takes up 2 hex chars + 1 space = 3 chars
            # For 16 bytes, that's 16 * 3 = 48 chars total.
            # If we have fewer than 16 bytes in this chunk, add enough spaces to reach 48.
            needed_spaces = 48 - String.length(hex_bytes)
            hex_bytes_padded = hex_bytes <> String.duplicate(" ", needed_spaces)

            # Convert to ASCII, replacing non-printable characters with "."
            ascii = chunk
            |> Enum.map(fn byte ->
                if byte in 32..126 do <<byte>> else "." end
            end)
            |> Enum.join()

            # Build the final line
            "#{offset_str}  #{hex_bytes_padded}  #{ascii}"
        end)
        |> Enum.join("\n")
    end

    def sbash(term) do
        term = "#{term}"
        term = String.replace(term, "'", "")
        if term == "" do "" else "'#{term}'" end
    end

    def ascii(string) do
        for <<c <- string>>,
            c == 32
            or c in 123..126
            or c in ?!..?@
            or c in ?[..?_
            or c in ?0..?9
            or c in ?A..?Z
            or c in ?a..?z,
        into: "" do
            <<c>>
        end
    end
    def ascii?(string) do
        string == ascii(string)
    end

    def alphanumeric(string) do
        for <<c <- string>>,
            c in ?0..?9
            or c in ?A..?Z
            or c in ?a..?z,
        into: "" do
            <<c>>
        end
    end
    def alphanumeric?(string) do
        string == alphanumeric(string)
    end

    def ascii_dash_underscore(string) do
        string
        |> String.to_charlist()
        |> Enum.filter(fn(char)->
            char in 97..122
            || char in 65..90
            || char in 48..57
            || char in [95, 45] #"_-"
        end)
        |> List.to_string()
    end

    def alphanumeric_hostname(string) do
        string
        |> String.to_charlist()
        |> Enum.filter(fn(char)->
            char in 97..122
            || char in 48..57
            || char in [45] #"-"
        end)
        |> List.to_string()
    end

    def sext(path) do
        ext = Path.extname(path)
        |> alphanumeric()
        "." <> ext
    end

    def url(url) do
        String.trim(url, "/")
    end

    def url(url, path) do
        String.trim(url, "/") <> path
    end

    def url_to_ws(url, path) do
        url = String.trim(url, "/") <> path
        url = String.replace(url, "https://", "wss://")
        url = String.replace(url, "http://", "ws://")
    end

    def https_ssl_opts(url) do
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
            _ -> %{}
        end
    end

    def get(url, headers \\ %{}, opts \\ %{}) do
        opts = Map.merge(opts, https_ssl_opts(url))
        :comsat_http.get(url, headers, opts)
    end

    def get_json(url, headers \\ %{}, opts \\ %{}) do
        {labels, opts} = Map.pop(opts, :labels, :attempt_atom)
        {:ok, %{body: body}} = get(url, headers, opts)
        #IO.inspect body
        JSX.decode!(body, [{:labels, labels}])
    end

    def delete(url, body, headers \\ %{}, opts \\ %{}) do
        opts = Map.merge(opts, https_ssl_opts(url))
        body = if !is_binary(body) do JSX.encode!(body) else body end
        :comsat_http.delete(url, headers, body, opts)
    end

    def delete_json(url, body, headers \\ %{}, opts \\ %{}) do
        {labels, opts} = Map.pop(opts, :labels, :attempt_atom)
        {:ok, %{body: body}} = delete(url, body, headers, opts)
        JSX.decode!(body, [{:labels, labels}])
    end

    def post(url, body, headers \\ %{}, opts \\ %{}) do
        opts = Map.merge(opts, https_ssl_opts(url))
        body = if !is_binary(body) do JSX.encode!(body) else body end
        :comsat_http.post(url, headers, body, opts)
    end

    def post_json(url, body, headers \\ %{}, opts \\ %{}) do
        {labels, opts} = Map.pop(opts, :labels, :attempt_atom)
        {:ok, %{body: body}} = post(url, body, headers, opts)
        #IO.inspect body
        JSX.decode!(body, [{:labels, labels}])
    end

    def put(url, body, headers \\ %{}, opts \\ %{}) do
        opts = Map.merge(opts, https_ssl_opts(url))
        body = if !is_binary(body) do JSX.encode!(body) else body end
        :comsat_http.put(url, headers, body, opts)
    end

    def put_json(url, body, headers \\ %{}, opts \\ %{}) do
        {labels, opts} = Map.pop(opts, :labels, :attempt_atom)
        {:ok, %{body: body}} = put(url, body, headers, opts)
        JSX.decode!(body, [{:labels, labels}])
    end

    def b3sum(path) do
        Base.hex_encode32(Blake3.hash(File.read!(path)), padding: false, case: :lower)
    end

    def pad_bitstring_to_bytes(bitstring) do
        bits = bit_size(bitstring)
        padding = rem(8 - rem(bits, 8), 8)
        <<bitstring::bitstring, 0::size(padding)>>
    end

    def set_bit(bin, i) when is_bitstring(bin) and is_integer(i) do
        n = bit_size(bin)

        if i < 0 or i >= n do
          raise ArgumentError, "Bit index out of range: #{i} (size is #{n})"
        end

        left_size = i
        << left::size(left_size), _old_bit::size(1), right::bitstring >> = bin
        << left::size(left_size), 1::size(1), right::bitstring >>
    end

    def get_bit(bin, i) when is_bitstring(bin) and is_integer(i) do
        n = bit_size(bin)

        if i < 0 or i >= n do
          raise ArgumentError, "Bit index out of range: #{i} (size is #{n})"
        end

        left_size = i
        # Pattern-match to extract the bit
        <<_left::size(left_size), bit::size(1), _right::bitstring>> = bin
        bit == 1
    end

    def popcnt(bs) when is_bitstring(bs) do
      pc4 = <<0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4>>

      total_bits = bit_size(bs)
      full_bytes = div(total_bits, 8)
      rem_bits   = rem(total_bits, 8)

      <<bytes::binary-size(full_bytes), rest::bitstring-size(rem_bits)>> = bs

      # byte popcount via two 4-bit lookups per byte, looped with an anonymous recursion
      byte_count =
        (fn loop, i, acc ->
           if i == byte_size(bytes) do
             acc
           else
             b  = :binary.at(bytes, i)
             hi = :erlang.bsr(b, 4)
             lo = :erlang.band(b, 15)
             loop.(loop, i + 1, acc + :binary.at(pc4, hi) + :binary.at(pc4, lo))
           end
         end).(fn loop, i, acc ->
                if i == byte_size(bytes) do
                  acc
                else
                  b  = :binary.at(bytes, i)
                  hi = :erlang.bsr(b, 4)
                  lo = :erlang.band(b, 15)
                  loop.(loop, i + 1, acc + :binary.at(pc4, hi) + :binary.at(pc4, lo))
                end
              end, 0, 0)

      # tail (≤7 bits): pack to int and Kernighan-count with an anonymous recursion
      tail_count =
        if rem_bits == 0 do
          0
        else
          <<v::unsigned-integer-size(rem_bits)>> = rest
          (fn k, x, a -> if x == 0, do: a, else: k.(k, :erlang.band(x, x - 1), a + 1) end).(
            fn k, x, a -> if x == 0, do: a, else: k.(k, :erlang.band(x, x - 1), a + 1) end,
            v, 0
          )
        end

      byte_count + tail_count
    end

    def index_of(list, key) do
        {result, index} = Enum.reduce_while(list, {nil, 0}, fn(element, {result, index})->
            if element == key do
                {:halt, {element, index}}
            else
                {:cont, {nil, index+1}}
            end
        end)
        if result do
            index
        end
    end

    def verify_time_sync() do
        {res, _} = System.shell("timedatectl status")
        String.contains?(res, "System clock synchronized: yes")
    end

    def ensure_copied(bin) when is_binary(bin) do
      if :binary.referenced_byte_size(bin) > byte_size(bin) do
        IO.inspect {:ensure_copied, :binary.referenced_byte_size(bin), byte_size(bin)}
        :binary.copy(bin)
      else
        bin
      end
    end
end
