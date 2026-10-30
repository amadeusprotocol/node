defmodule ForkRepair do
  @fork_parent "FLMxT7xVPr6oUGYPnXbuKiL6JjyG2t6VYQN54tQJnrX3" #88971607
  @fork_parent_height 88_971_607
  @dead ~w(12zqmbHJEHLdbfGYZSsUan9vajmzjxFiG1tYC4jSGuzJ
           78aDDhJoxUyvJh4Mb16en2jeknsmzcWtJJaktqBERB8F
           D1SZUXXbdh6PefVQ9MFjhRBEpzFaM8MyHwKyip76zAKu)

  def dead_hashes() do
    if Application.fetch_env!(:ama, :testnet), do: [], else: Enum.map(@dead, &Base58.decode/1)
  end

  def run() do
    dead = dead_hashes()
    :persistent_term.put(SoftforkDenyHash, dead)
    if Enum.any?(dead, &DB.Entry.in_chain/1) do
      parent = Base58.decode(@fork_parent)
      %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
      if DB.Chain.rooted_height() > @fork_parent_height do
        RocksDB.put("rooted_tip", parent, %{db: db, cf: cf.sysconf})
      end
      case DB.Chain.rewind(parent) do
        true -> IO.puts "fork repair: left dead branch, rewound to #{@fork_parent} (#{@fork_parent_height})"
        false -> IO.puts "fork repair: rewind refused, still on dead branch"
      end
    end
  end
end
