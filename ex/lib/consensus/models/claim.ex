defmodule Claim do
  #what attestations and consensuses sign for an applied entry:
  #  entry_height(u64 big) || entry_hash || root_contractstate || root_receipts
  #consensuses and attestations are stored and compared by Claim.hash

  @fields [:entry_height, :entry_hash, :root_contractstate, :root_receipts]

  #MMR leaves below the claim fork (epoch 881, testnet 41) are entry hashes
  def first_leaf_height(), do: if(Application.fetch_env!(:ama, :testnet), do: 4_100_000, else: 88_100_000)

  def build(height, entry_hash, root_contractstate, root_receipts) do
    %{entry_height: height, entry_hash: entry_hash, root_contractstate: root_contractstate, root_receipts: root_receipts}
  end

  def take(map), do: Map.take(map, @fields)

  def pack(c), do: <<c.entry_height::64, c.entry_hash::binary, c.root_contractstate::binary, c.root_receipts::binary>>

  def hash(c), do: :crypto.hash(:sha256, pack(c))

  def mmr_leaf(c) do
    if c.entry_height >= first_leaf_height(), do: hash(c), else: c.entry_hash
  end

  def valid?(c) do
    is_integer(c[:entry_height]) and c.entry_height >= 0 and c.entry_height <= 0x7FFF_FFFF_FFFF_FFFF
      and hash32?(c[:entry_hash]) and hash32?(c[:root_contractstate]) and hash32?(c[:root_receipts])
  end

  def for_height?(c, height), do: valid?(c) and c.entry_height == height

  defp hash32?(b), do: is_binary(b) and byte_size(b) == 32
end
