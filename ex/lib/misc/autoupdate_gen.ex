defmodule AutoUpdateGen do
  use GenServer

  #github throttles aggressive callers
  @poll_base_ms 30 * 60_000
  @poll_jitter_ms 30 * 60_000

  @api_timeout 30_000
  @dl_timeout 120_000

  def start_link() do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  def init(state) do
    schedule_tick()
    {:ok, state}
  end

  def handle_info(:tick, state) do
    state = tick(state)
    schedule_tick()
    {:noreply, state}
  end

  defp schedule_tick() do
    :erlang.send_after(@poll_base_ms + :rand.uniform(@poll_jitter_ms), self(), :tick)
  end

  def tick(state) do
    upgrade()
    state
  end

  def upgrade(is_boot \\ false) do
    try do
      check_for_update(is_boot)
    rescue
      e -> IO.inspect {:autoupdate_error, e}
    catch
      kind, reason -> IO.inspect {:autoupdate_error, kind, reason}
    end
  end

  defp check_for_update(is_boot) do
    with {:ok, body} <- http_get("https://api.github.com/repos/amadeusprotocol/node/releases/latest", @api_timeout),
         {:ok, json} <- decode_json(body) do
      #cheap gate on the (untrusted) tag; the authoritative check is the SIGNED manifest
      if version_lt?(Application.fetch_env!(:ama, :version), to_string(json[:tag_name])) do
        assets = json[:assets] || []
        asset = fn name -> Enum.find_value(assets, & &1[:name] == name and &1[:browser_download_url]) end
        bin_url = asset.("amadeusd")
        sig_url = asset.("amadeusd.sig")
        #fail-closed: a release without the signed bundle is never installed
        if bin_url && sig_url do
          with {:ok, bin} <- http_get(bin_url, @dl_timeout),
               {:ok, sigfile} <- http_get(sig_url, @dl_timeout) do
            IO.inspect {:downloading_upgrade, bin_url}
            maybe_install(bin, sigfile, is_boot)
          else
            err -> IO.inspect {:autoupdate_download_failed, err}
          end
        end
      end
    else
      #network error, rate limit (403), timeout, or bad json — skip; retry next tick
      err -> IO.inspect {:autoupdate_check_skipped, err}
    end
  end

  #never raises: any transport error / non-200 / throttle becomes {:error, _}
  defp http_get(url, timeout) do
    try do
      case :comsat_http.get(url, %{}, https_opts(%{timeout: timeout})) do
        {:ok, %{status_code: 200, body: body}} -> {:ok, body}
        {:ok, %{status_code: code}} -> {:error, {:http_status, code}}
        other -> {:error, other}
      end
    rescue
      e -> {:error, e}
    catch
      kind, reason -> {:error, {kind, reason}}
    end
  end

  defp decode_json(body) do
    {:ok, JSX.decode!(body, labels: :attempt_atom)}
  rescue
    _ -> {:error, :bad_json}
  catch
    _, _ -> {:error, :bad_json}
  end

  #amadeusd.sig bundles the signed manifest line + its armored SSHSIG. only swap if
  #the manifest is signed by a pinned key, the binary's hash matches the (signed)
  #manifest, and the (signed) version is strictly newer than both what we run and
  #the highest version we ever accepted (anti-rollback).
  defp maybe_install(bin, sigfile, is_boot) do
    with {:ok, manifest, sig} <- split_bundle(sigfile),
         :ok <- AutoUpdateReleaseVerify.verify(manifest, sig),
         {:ok, mver, msha} <- parse_manifest(manifest),
         true <- sha256_hex(bin) == msha or {:hash_mismatch, msha, sha256_hex(bin)},
         true <- version_accepted?(mver) or {:rejected_version, mver} do
      cwd_dir = File.cwd!()
      path_tmp = Path.join(cwd_dir, "amadeusd_tmp")
      path = Path.join(cwd_dir, "amadeusd")
      File.write!(path_tmp, bin)
      File.rename!(path_tmp, path)
      File.chmod!(path, 0o755)
      bump_floor(mver)
      IO.inspect {:autoupdate_verified, mver}
      restart(is_boot)
    else
      other -> IO.inspect {:autoupdate_rejected, other}
    end
  end

  defp restart(is_boot) do
    cond do
      is_boot -> :erlang.halt()
      DB.Chain.is_validator() ->
        FabricGen.exitAfterMySlot()

        now_height = DB.Chain.height()
        Process.sleep(30*1000)
        delta = DB.Chain.height() - now_height
        if delta <= 3 do
          :erlang.halt()
        end

      true -> :erlang.halt()
    end
  end

  #the bundle is the signed manifest bytes followed by the armored SSHSIG. split at
  #the armor header: everything before it is the EXACT bytes that were signed.
  defp split_bundle(sigfile) do
    marker = "-----BEGIN SSH SIGNATURE-----"
    case String.split(sigfile, marker, parts: 2) do
      [manifest, rest] when manifest != "" -> {:ok, manifest, marker <> rest}
      _ -> :error
    end
  end

  #manifest is one line: "<version> <sha256_hex>"
  defp parse_manifest(manifest) do
    case String.split(manifest) do
      [ver, sha | _] -> {:ok, ver, String.downcase(sha)}
      _ -> :error
    end
  end

  defp sha256_hex(bin), do: :crypto.hash(:sha256, bin) |> Base.encode16(case: :lower)

  defp version_accepted?(mver) do
    version_lt?(Application.fetch_env!(:ama, :version), mver) and version_lt?(read_floor(), mver)
  end

  defp floor_path(), do: Path.join(Application.fetch_env!(:ama, :work_folder), "release_min_version")
  defp read_floor() do
    case File.read(floor_path()) do
      {:ok, v} -> String.trim(v)
      _ -> "0.0.0"
    end
  end
  defp bump_floor(ver), do: File.write(floor_path(), ver)

  #verify_peer against certifi's Mozilla CA bundle (compiled into the certifi hex
  #package and packed into the release binary — NOT the OS store, so it works even
  #where the host CA dir is empty/stale). no hardcoded SNI: auto_sni derives it from
  #each URL host so the github.com -> CDN download redirect still verifies the
  #hostname correctly at every hop.
  defp https_opts(extra \\ %{}) do
    Map.merge(%{
      auto_sni: true,
      ssl_options: [
        {:verify, :verify_peer},
        {:depth, 99},
        {:cacerts, :certifi.cacerts()},
        {:partial_chain, &Photon.SSLPin.partial_chain/1},
        {:customize_hostname_check, [{:match_fun, :public_key.pkix_verify_hostname_match_fun(:https)}]}
      ]
    }, extra)
  end

  def version_lt?(local, remote), do: parse_version(local) < parse_version(remote)

  def parse_version(str) do
    parts = str
    |> to_string()
    |> String.trim()
    |> String.trim_leading("v")
    |> String.split(".")
    |> Enum.map(fn part ->
      case Integer.parse(part) do
        {n, _} -> n
        :error -> 0
      end
    end)
    case parts do
      [a] -> {a, 0, 0}
      [a, b] -> {a, b, 0}
      [a, b, c | _] -> {a, b, c}
      _ -> {0, 0, 0}
    end
  end
end
