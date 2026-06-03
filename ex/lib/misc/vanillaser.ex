defmodule VanillaSer do
    @max_depth 64
    @max_payload_bytes 64 * 1024 * 1024

    def validate(binary) do
        {term, ""} = decode(binary)
        if binary == encode(term) do
            term
        end
    end

    def encode(term, acc \\ <<>>) do
        cond do
            term == nil -> <<acc::binary, 0>>
            term == true -> <<acc::binary, 1>>
            term == false -> <<acc::binary, 2>>
            is_integer(term) ->
                acc = <<acc::binary, 3>>
                encode_varint(term, acc)
            is_binary(term) ->
                acc = <<acc::binary, 5>>
                acc = encode_varint(byte_size(term), acc)
                <<acc::binary, term::binary>>
            is_atom(term) ->
                term = "#{term}"
                acc = <<acc::binary, 5>>
                acc = encode_varint(byte_size(term), acc)
                <<acc::binary, term::binary>>
            is_list(term) ->
                acc = <<acc::binary, 6>>
                acc = encode_varint(length(term), acc)
                Enum.reduce(term, acc, fn(member, acc)->
                    encode(member, acc)
                end)
            is_map(term) ->
                acc = <<acc::binary, 7>>
                acc = encode_varint(:erlang.map_size(term), acc)

                Enum.sort_by(term, & elem(&1,0))
                |> Enum.reduce(acc, fn({k, v}, acc)->
                    acc = encode(k, acc)
                    encode(v, acc)
                end)
            #ENABLE LATER
            #is_map(term) ->
            #    acc = <<acc::binary, 7>>
            #    acc = encode_varint(:erlang.map_size(term), acc)
            #
            #    Enum.map(term, fn {k, v} ->
            #      {encode(k, <<>>), encode(v, <<>>)}
            #    end)
            #    |> Enum.sort_by(& elem(&1,0))
            #    |> Enum.reduce(acc, fn({k, v}, acc)->
            #    acc = acc <> k
            #    acc <> v
            #    end)
        end
    end
    def encode_varint(0, acc) do acc <> <<0>> end
    def encode_varint(int, acc) do
        sign = if int >= 0 do 0 else 1 end
        bin = :binary.encode_unsigned(abs(int))
        acc <> <<sign::1, byte_size(bin)::7>> <> bin
    end

    defp safe_key(k) when is_binary(k) do
        try do
            String.to_existing_atom(k)
        rescue
            ArgumentError -> k
        end
    end

    def decode!(binary) do
        {term, ""} = decode(binary)
        term
    end
    def decode(bin), do: decode(bin, 0)

    def decode(<<type::8, rest::binary>>, depth) when depth <= @max_depth do
        case type do
            0 -> {nil, rest}
            1 -> {true, rest}
            2 -> {false, rest}
            3 -> decode_varint(rest)
            5 ->
                {int, rest} = decode_varint(rest)
                if int < 0 or int > @max_payload_bytes or int > byte_size(rest) do
                    raise ArgumentError, "vanillaser: bad payload length #{int}"
                end
                <<payload::size(int)-binary, rest::binary>> = rest
                {payload, rest}
            6 ->
                {int, rest} = decode_varint(rest)
                if int < 0 or int > byte_size(rest) do
                    raise ArgumentError, "vanillaser: bad list length #{int}"
                end
                if int == 0 do {[], rest} else
                    Enum.reduce(1..int, {[], rest}, fn(_, {acc, rest})->
                        {v, rest} = decode(rest, depth + 1)
                        {acc ++ [v], rest}
                    end)
                end
            7 ->
                {int, rest} = decode_varint(rest)
                if int < 0 or int > byte_size(rest) do
                    raise ArgumentError, "vanillaser: bad map length #{int}"
                end
                if int == 0 do {%{}, rest} else
                    Enum.reduce(1..int, {%{}, rest}, fn(_, {acc, rest})->
                        {k, rest} = decode(rest, depth + 1)
                        {v, rest} = decode(rest, depth + 1)
                        key = if is_binary(k) do safe_key(k) else k end
                        {Map.put(acc, key, v), rest}
                    end)
                end
        end
    end
    def decode(_bin, _depth) do
        raise ArgumentError, "vanillaser: max recursion depth exceeded"
    end

    def decode_varint(<<sign::1, len::7, payload::size(len*8), rest::binary>>) do
        if len > 16 do
            raise ArgumentError, "vanillaser: varint length #{len} > 16 bytes"
        end
        if sign == 0 do
            {payload, rest}
        else
            {-payload, rest}
        end
    end
end
