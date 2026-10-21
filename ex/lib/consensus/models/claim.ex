defmodule Claim do
  #what attestations and consensuses sign for an applied entry
  #  fork:   entry_height(u64 big) || entry_hash || root_contractstate || root_receipts
  #  legacy: entry_hash || mutations_hash (below RDBProtocol.forkheight)
  #consensuses and attestations are stored and compared by Claim.hash

  @fields [:entry_height, :entry_hash, :root_contractstate, :root_receipts]
  @legacy_fields [:entry_hash, :mutations_hash]

  def fork?(height), do: height >= RDBProtocol.forkheight()

  def build(height, entry_hash, mutations_hash, root_contractstate, root_receipts) do
    if fork?(height) do
      %{entry_height: height, entry_hash: entry_hash, root_contractstate: root_contractstate, root_receipts: root_receipts}
    else
      %{entry_hash: entry_hash, mutations_hash: mutations_hash}
    end
  end

  def take(map = %{mutations_hash: _}), do: Map.take(map, @legacy_fields)
  def take(map), do: Map.take(map, @fields)

  def pack(%{entry_hash: entry_hash, mutations_hash: mutations_hash}), do: <<entry_hash::binary, mutations_hash::binary>>
  def pack(c), do: <<c.entry_height::64, c.entry_hash::binary, c.root_contractstate::binary, c.root_receipts::binary>>

  def hash(%{mutations_hash: mutations_hash}), do: mutations_hash
  def hash(c), do: :crypto.hash(:sha256, pack(c))

  #legacy MMR leaves are entry hashes
  def mmr_leaf(%{entry_hash: entry_hash, mutations_hash: _}), do: entry_hash
  def mmr_leaf(c), do: hash(c)

  def valid?(c = %{mutations_hash: _}), do: hash32?(c.entry_hash) and hash32?(c.mutations_hash)
  def valid?(c) do
    is_integer(c[:entry_height]) and c.entry_height >= 0 and c.entry_height <= 0x7FFF_FFFF_FFFF_FFFF and fork?(c.entry_height)
      and hash32?(c[:entry_hash]) and hash32?(c[:root_contractstate]) and hash32?(c[:root_receipts])
  end

  #the shape must be the one of the entry's height
  def for_height?(c = %{mutations_hash: _}, height), do: valid?(c) and !fork?(height)
  def for_height?(c, height), do: valid?(c) and c.entry_height == height

  defp hash32?(b), do: is_binary(b) and byte_size(b) == 32
end
