defmodule Ama.MixProject do
  use Mix.Project

  @app :ama

  def project do
    [
      app: @app,
      version: "1.5.6",
      elixir: ">= 1.19.0",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      build_embedded: Mix.env == :prod,
      releases: [{@app, release()}],
    ]
  end

  def application do
    apps = [
      extra_applications: [:iex, :logger, :crypto, :ssl, :inets]
    ]
    if Mix.env() == :prod do
      [{:mod, {Ama.Bakeware, []}} | apps]
    else
      [{:mod, {Ama, []}} | apps]
    end
  end

  defp deps do
    [
      {:bakeware, git: "https://github.com/vans163/bakeware", branch: "main", runtime: false},

      {:photon, git: "https://github.com/vans163/photon.git"},
      {:mnesia_kv, git: "https://github.com/xenomorphtech/mnesia_kv.git"},

      {:rustler, ">= 0.36.1", optional: true},
      {:blake3_ex, git: "https://github.com/vans163/blake3", branch: "finalize_xof"},
      {:bls_ex, git: "https://github.com/amadeusprotocol/bls_ex"},
      {:reedsolomon_ex, git: "https://github.com/amadeusprotocol/reedsolomon_ex"},
      {:wasmer_ex, git: "https://github.com/amadeusprotocol/wasmer_ex"},

      {:comsat, git: "https://github.com/vans163/ComSat.git"},
      {:ex_stun, git: "https://github.com/elixir-webrtc/ex_stun.git"},
      {:x509, git: "https://github.com/voltone/x509"},
    ]
  end

  defp release do
    [
      overwrite: true,
      steps: [:assemble, &Bakeware.assemble/1],
      strip_beams: Mix.env() == :prod,
      bakeware: [
        compression_level: 1,
        #compression_level: 19,
        start_command: "start_iex"
      ],
    ]
  end

  def cli do
    [preferred_envs: [release: :prod]]
  end
end
