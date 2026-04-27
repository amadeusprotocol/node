defmodule EntryGenesis do
    @signer <<140, 27, 75, 245, 48, 112, 140, 244, 78, 114, 11, 45, 8, 201, 199,
         184, 71, 69, 96, 112, 52, 204, 31, 56, 143, 115, 222, 87, 7, 185, 3, 168,
         252, 90, 91, 114, 16, 244, 47, 228, 198, 82, 12, 130, 10, 126, 118, 193>>
    @pop <<175, 176, 86, 129, 118, 228, 182, 86, 225, 187, 236, 131, 170, 81, 121, 174,
         164, 44, 71, 123, 136, 151, 170, 187, 43, 43, 211, 181, 163, 103, 93, 122,
         11, 207, 92, 1, 190, 71, 46, 129, 210, 134, 62, 169, 152, 161, 189, 58, 18,
         246, 6, 151, 128, 196, 116, 93, 20, 204, 153, 217, 81, 205, 1, 133, 65, 204,
         177, 138, 74, 8, 104, 109, 214, 59, 245, 51, 47, 218, 15, 207, 190, 73, 40,
         128, 108, 147, 250, 88, 241, 61, 129, 47, 189, 173, 118, 76>>
    @attestation %{
       signature: <<151, 160, 206, 230, 190, 143, 68, 181, 248, 53, 105, 176, 56,
         44, 82, 68, 252, 20, 61, 83, 33, 137, 74, 216, 149, 11, 242, 157, 237, 53,
         139, 120, 202, 52, 30, 65, 9, 155, 243, 52, 53, 41, 236, 86, 235, 128, 52,
         74, 12, 80, 187, 82, 174, 138, 121, 69, 159, 251, 97, 201, 238, 119, 163,
         203, 122, 207, 179, 5, 178, 32, 145, 32, 183, 62, 184, 189, 136, 134, 80,
         7, 193, 218, 133, 171, 154, 215, 219, 77, 33, 161, 152, 129, 142, 35, 9,
         183>>,
       mutations_hash: <<72, 67, 216, 106, 224, 102, 200, 77, 84, 86, 71, 38, 221,
         89, 178, 87, 170, 13, 141, 117, 29, 103, 251, 177, 92, 143, 88, 218, 21,
         177, 139, 196>>,
       signer: <<140, 27, 75, 245, 48, 112, 140, 244, 78, 114, 11, 45, 8, 201, 199,
         184, 71, 69, 96, 112, 52, 204, 31, 56, 143, 115, 222, 87, 7, 185, 3, 168,
         252, 90, 91, 114, 16, 244, 47, 228, 198, 82, 12, 130, 10, 126, 118, 193>>,
       entry_hash: <<250, 154, 199, 170, 114, 250, 155, 84, 2, 215, 37, 236, 138,
         98, 19, 87, 19, 163, 21, 138, 131, 205, 205, 189, 176, 217, 5, 112, 225,
         13, 15, 217>>
     }
    @genesis_entry %{
       header: <<131, 116, 0, 0, 0, 8, 119, 2, 100, 114, 109, 0, 0, 0, 32, 85, 13,
         37, 23, 114, 150, 131, 140, 136, 174, 76, 72, 122, 45, 180, 165, 94, 229,
         194, 27, 2, 87, 249, 159, 121, 177, 233, 167, 179, 0, 217, 219, 119, 6,
         104, 101, 105, 103, 104, 116, 97, 0, 119, 9, 112, 114, 101, 118, 95, 104,
         97, 115, 104, 109, 0, 0, 0, 0, 119, 9, 112, 114, 101, 118, 95, 115, 108,
         111, 116, 98, 255, 255, 255, 255, 119, 6, 115, 105, 103, 110, 101, 114,
         109, 0, 0, 0, 48, 140, 27, 75, 245, 48, 112, 140, 244, 78, 114, 11, 45, 8,
         201, 199, 184, 71, 69, 96, 112, 52, 204, 31, 56, 143, 115, 222, 87, 7, 185,
         3, 168, 252, 90, 91, 114, 16, 244, 47, 228, 198, 82, 12, 130, 10, 126, 118,
         193, 119, 4, 115, 108, 111, 116, 97, 0, 119, 8, 116, 120, 115, 95, 104, 97,
         115, 104, 109, 0, 0, 0, 32, 175, 19, 73, 185, 245, 249, 161, 166, 160, 64,
         77, 234, 54, 220, 201, 73, 155, 203, 37, 201, 173, 193, 18, 183, 204, 154,
         147, 202, 228, 31, 50, 98, 119, 2, 118, 114, 109, 0, 0, 0, 96, 181, 221,
         57, 62, 159, 101, 228, 75, 242, 59, 58, 92, 179, 234, 71, 120, 2, 232, 181,
         156, 102, 142, 148, 152, 180, 116, 198, 158, 94, 152, 24, 27, 115, 224,
         103, 169, 12, 237, 98, 44, 113, 237, 198, 210, 218, 83, 162, 181, 5, 65,
         253, 232, 57, 140, 196, 121, 187, 108, 46, 68, 159, 45, 220, 62, 254, 201,
         44, 135, 201, 126, 206, 74, 140, 239, 177, 95, 169, 40, 181, 104, 167, 84,
         50, 207, 85, 35, 42, 10, 36, 196, 9, 13, 156, 79, 186, 117>>,
       signature: <<179, 146, 253, 87, 173, 166, 85, 68, 73, 181, 204, 201, 40, 101,
         234, 64, 243, 202, 202, 35, 214, 166, 101, 4, 82, 168, 131, 119, 230, 126,
         98, 253, 153, 117, 239, 112, 203, 145, 116, 17, 53, 235, 113, 23, 73, 26,
         91, 171, 11, 28, 244, 153, 250, 238, 23, 205, 114, 124, 195, 112, 171, 200,
         45, 108, 129, 26, 219, 122, 24, 43, 162, 187, 120, 106, 116, 236, 25, 140,
         129, 215, 83, 78, 184, 11, 9, 108, 22, 132, 47, 26, 250, 246, 119, 252, 81,
         91>>,
       hash: <<250, 154, 199, 170, 114, 250, 155, 84, 2, 215, 37, 236, 138, 98, 19,
         87, 19, 163, 21, 138, 131, 205, 205, 189, 176, 217, 5, 112, 225, 13, 15,
         217>>,
       header_unpacked: %{
         slot: 0,
         height: 0,
         signer: <<140, 27, 75, 245, 48, 112, 140, 244, 78, 114, 11, 45, 8, 201,
           199, 184, 71, 69, 96, 112, 52, 204, 31, 56, 143, 115, 222, 87, 7, 185, 3,
           168, 252, 90, 91, 114, 16, 244, 47, 228, 198, 82, 12, 130, 10, 126, 118,
           193>>,
         vr: <<181, 221, 57, 62, 159, 101, 228, 75, 242, 59, 58, 92, 179, 234, 71,
           120, 2, 232, 181, 156, 102, 142, 148, 152, 180, 116, 198, 158, 94, 152,
           24, 27, 115, 224, 103, 169, 12, 237, 98, 44, 113, 237, 198, 210, 218, 83,
           162, 181, 5, 65, 253, 232, 57, 140, 196, 121, 187, 108, 46, 68, 159, 45,
           220, 62, 254, 201, 44, 135, 201, 126, 206, 74, 140, 239, 177, 95, 169,
           40, 181, 104, 167, 84, 50, 207, 85, 35, 42, 10, 36, 196, 9, 13, 156, 79,
           186, 117>>,
         prev_hash: "",
         dr: <<85, 13, 37, 23, 114, 150, 131, 140, 136, 174, 76, 72, 122, 45, 180,
           165, 94, 229, 194, 27, 2, 87, 249, 159, 121, 177, 233, 167, 179, 0, 217,
           219>>,
         prev_slot: -1,
         txs_hash: <<175, 19, 73, 185, 245, 249, 161, 166, 160, 64, 77, 234, 54,
           220, 201, 73, 155, 203, 37, 201, 173, 193, 18, 183, 204, 154, 147, 202,
           228, 31, 50, 98>>
       },
       txs: []
     }

    def signer() do
        @signer
    end

    def pop() do
        @pop
    end

    def attestation() do
        @attestation
    end

    def get() do
        @genesis_entry
    end

    def generate() do
        pk = Application.fetch_env!(:ama, :trainer_pk)
        sk = Application.fetch_env!(:ama, :trainer_sk)

        entropy_seed = """
        January 27, 2025

        Tech stocks tank as a Chinese competitor threatens to upend the AI frenzy; Nvidia sinks nearly 17%
        """
        dr = Blake3.hash(entropy_seed)
        vr = BlsEx.sign!(sk, dr<>dr<>dr, BLS12AggSig.dst_vrf())

        entry = %{
          header_unpacked: %{
            slot: 0,
            height: 0,
            prev_slot: -1,
            prev_hash: <<>>,
            dr: dr,
            vr: vr,
            signer: pk,
          },
          txs: [],
        }
        entry_signed = Entry.sign(sk, entry)

        %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
        rtx = RocksDB.transaction(db)
        #{mutations, _} = BIC.Base.call_exit(%{entry: entry})
        mutations = []
        mutations_hash = RDB.vecpak_encode(mutations) |> Blake3.hash()
        attestation = Attestation.sign(sk, entry_signed.hash, 0, mutations_hash, :binary.copy(<<0>>, 32), :binary.copy(<<0>>, 32), :binary.copy(<<0>>, 32))

        pop = BlsEx.sign!(sk, pk, BLS12AggSig.dst_pop())

        IO.inspect {entry_signed, attestation, pop}, limit: :infinity
        :ok
    end

    def generate_testnet() do
      %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
      if !RocksDB.get("temporal_tip", %{db: db, cf: cf.sysconf}) do
        IO.puts "making testnet.."

        pk = Application.fetch_env!(:ama, :trainer_pk)
        sk = Application.fetch_env!(:ama, :trainer_sk)

        if length(Application.fetch_env!(:ama, :keys)) < 10 do
          new_keys = Enum.map(0..9, fn(_)-> :crypto.strong_rand_bytes(64) |> Base58.encode() end)
          |> Enum.join("\n")
          workdir = Application.fetch_env!(:ama, :work_folder)
          File.write!(Path.join([workdir, "seeds"]), new_keys)
          IO.puts "seeded testnet please restart node"
          :erlang.halt()
        end

        entropy_seed = :crypto.strong_rand_bytes(512)
        dr = :crypto.hash(:sha256, entropy_seed)
        vr = BlsEx.sign!(sk, dr<>dr<>dr, BLS12AggSig.dst_vrf())

        entry = %{
          header: %{
            slot: 0,
            height: 0,
            prev_slot: -1,
            prev_hash: <<>>,
            dr: dr,
            vr: vr,
            signer: pk,
          },
          txs: [],
        }
        entry_signed = Entry.sign(sk, entry)

        rtx = RocksDB.transaction(db)

        mutations_hash = RDB.vecpak_encode([]) |> Blake3.hash()
        attestation = Attestation.sign(sk, entry_signed.hash, 0, mutations_hash, :binary.copy(<<0>>, 32), :binary.copy(<<0>>, 32), :binary.copy(<<0>>, 32))

        pop = BlsEx.sign!(sk, pk, BLS12AggSig.dst_pop())

        DB.Entry.insert(entry_signed, %{rtx: rtx})
        DB.Entry.apply_into_main_chain(entry_signed, mutations_hash, [], [], "", "", %{rtx: rtx})
        RocksDB.put("temporal_tip", entry_signed.hash, %{rtx: rtx, cf: cf.sysconf})
        RocksDB.put("rooted_tip", entry_signed.hash, %{rtx: rtx, cf: cf.sysconf})

        validator_pks = Application.fetch_env!(:ama, :keys) |> Enum.map(& &1.pk)
        RocksDB.put("bic:epoch:validators:height:#{String.pad_leading("0", 12, "0")}",
          RDB.vecpak_encode(validator_pks), %{rtx: rtx, cf: cf.contractstate})
        RocksDB.put("bic:epoch:diff_bits", "8", %{rtx: rtx, cf: cf.contractstate})
        RocksDB.put("bic:epoch:segment_vr_hash", Blake3.hash(vr), %{rtx: rtx, cf: cf.contractstate})

        Enum.each(Application.fetch_env!(:ama, :keys), fn(key)->
          RocksDB.put("account:#{key.pk}:balance:AMA", "10300300123456789", %{rtx: rtx, cf: cf.contractstate})
          RocksDB.put("account:#{key.pk}:attribute:pop", key.pop, %{rtx: rtx, cf: cf.contractstate})
        end)
        rtx = RocksDB.transaction_commit(rtx)
      end
    end
end
