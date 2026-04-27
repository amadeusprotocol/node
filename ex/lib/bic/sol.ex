defmodule BIC.Sol do
    @preamble_size 240
    @matrix_size 1024
    @sol_size @preamble_size + @matrix_size
    def size() do
      @sol_size
    end

    def unpack(sol = <<epoch::32-little, _::binary>>) when epoch >= 156 do
    #def unpack(sol = <<epoch::32-little, _::binary>>) do
        <<epoch::32-little, segment_vr_hash::32-binary, sol_pk::48-binary, pop::96-binary, computor_pk::48-binary, nonce::12-binary, tensor_c::1024-binary>> = sol
        %{epoch: epoch, pk: sol_pk, pop: pop, computor: computor_pk, segment_vr_hash: segment_vr_hash, nonce: nonce, tensor_c: tensor_c}
    end
    def unpack(sol = <<epoch::32-little, _::binary>>) when epoch >= 1 do
        <<epoch::32-little, sol_pk::48-binary, pop::96-binary, computor_pk::48-binary, segment_vr::96-binary, _::binary>> = sol
        %{epoch: epoch, pk: sol_pk, pop: pop, computor: computor_pk, segment_vr: segment_vr}
    end
    def unpack(sol) do
        <<epoch::32-little, sol_pk::48-binary, pop::96-binary, computor_pk::48-binary, _::binary>> = sol
        %{epoch: epoch, pk: sol_pk, pop: pop, computor: computor_pk}
    end

    def unpack_testnet(sol = <<epoch::32-little, _::binary>>) do
        <<epoch::32-little, segment_vr_hash::32-binary, sol_pk::48-binary, pop::96-binary, computor_pk::48-binary, nonce::12-binary, tensor_c::1024-binary>> = sol
        %{epoch: epoch, pk: sol_pk, pop: pop, computor: computor_pk, segment_vr_hash: segment_vr_hash, nonce: nonce, tensor_c: tensor_c}
    end

    def verify_hash(epoch, hash) when epoch >= 244 do
        <<a, b, c, _::binary>> = hash
        a == 0 and b == 0 and c == 0
    end
    def verify_hash(epoch, hash) when epoch >= 156 do
        <<a, b, _::30-binary>> = hash
        a == 0 and b == 0
    end
    def verify_hash(epoch, hash) when epoch >= 1 do
        <<a, b, _::30-binary>> = hash
        a == 0 and b == 0
    end
    def verify_hash(_epoch, hash) do
        <<a, _::31-binary>> = hash
        a == 0
    end

    def verify_hash_diff(_epoch, hash, diff_bits) do
      <<a::size(diff_bits), _::bitstring>> = hash
      a == 0
    end

    def verify(sol = <<epoch::32-little, _::binary>>, opts \\ %{}) do
      cond do
        !!Application.fetch_env(:ama, :testnet)->
          usol = unpack_testnet(sol)
          if opts.segment_vr_hash != usol.segment_vr_hash, do: throw %{error: :segment_vr_hash}
          if byte_size(sol) != @sol_size, do: throw(%{error: :invalid_sol_seed_size})
          hash = Map.get_lazy(opts, :hash, fn()-> Blake3.hash(sol) end)
          vr_b3 = Map.get_lazy(opts, :vr_b3, fn()-> :crypto.strong_rand_bytes(32) end)
          verify_hash_diff(epoch, hash, opts.diff_bits) and RDB.freivalds(sol, vr_b3)
        epoch >= 295 ->
          usol = unpack(sol)
          if opts.segment_vr_hash != usol.segment_vr_hash, do: throw %{error: :segment_vr_hash}
          if byte_size(sol) != @sol_size, do: throw(%{error: :invalid_sol_seed_size})
          hash = Map.get_lazy(opts, :hash, fn()-> Blake3.hash(sol) end)
          vr_b3 = Map.get_lazy(opts, :vr_b3, fn()-> :crypto.strong_rand_bytes(32) end)
          verify_hash_diff(epoch, hash, opts.diff_bits) and RDB.freivalds(sol, vr_b3)
        epoch >= 282 ->
          usol = unpack(sol)
          if opts.segment_vr_hash != usol.segment_vr_hash, do: throw %{error: :segment_vr_hash}
          if byte_size(sol) != @sol_size, do: throw(%{error: :invalid_sol_seed_size})
          hash = Map.get_lazy(opts, :hash, fn()-> Blake3.hash(sol) end)
          vr_b3 = Map.get_lazy(opts, :vr_b3, fn()-> :crypto.strong_rand_bytes(32) end)
          verify_hash(epoch, hash) and RDB.freivalds(sol, vr_b3)
        epoch >= 260 ->
          if byte_size(sol) != @sol_size, do: throw(%{error: :invalid_sol_seed_size})
          hash = Map.get_lazy(opts, :hash, fn()-> Blake3.hash(sol) end)
          vr_b3 = Map.get_lazy(opts, :vr_b3, fn()-> :crypto.strong_rand_bytes(32) end)
          verify_hash(epoch, hash) and RDB.freivalds(sol, vr_b3)
        epoch >= 156 ->
          if byte_size(sol) != @sol_size, do: throw(%{error: :invalid_sol_seed_size})
          hash = Map.get_lazy(opts, :hash, fn()-> Blake3.hash(sol) end)
          verify_hash(epoch, hash) and Blake3.freivalds(sol)
        epoch >= 1 ->
          if byte_size(sol) != 320, do: throw(%{error: :invalid_sol_seed_size})
          throw(%{error: :null})
        true ->
          if byte_size(sol) != 256, do: throw(%{error: :invalid_sol_seed_size})
          throw(%{error: :null})
      end
    end
end
