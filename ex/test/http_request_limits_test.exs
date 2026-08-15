defmodule Ama.MultiServerRequestLimitsTest do
  use ExUnit.Case, async: true

  test "bounds incomplete and complete request lines" do
    assert Ama.MultiServer.validate_request_buffer(%{buf: :binary.copy("a", 8 * 1024)}) == :ok

    assert Ama.MultiServer.validate_request_buffer(%{buf: :binary.copy("a", 8 * 1024 + 1)}) ==
             {:error, :request_line_too_large}

    oversized = :binary.copy("a", 8 * 1024 + 1) <> "\r\nHost: node\r\n\r\n"

    assert Ama.MultiServer.validate_request_buffer(%{buf: oversized}) ==
             {:error, :request_line_too_large}
  end

  test "bounds aggregate headers" do
    assert Ama.MultiServer.validate_request_buffer(%{
             step: :headers,
             buf: :binary.copy("a", 32 * 1024 + 1)
           }) ==
             {:error, :headers_too_large}

    assert Ama.MultiServer.validate_request_buffer(%{
             step: :headers,
             buf: :binary.copy("a", 32 * 1024)
           }) == :ok
  end

  test "enforces idle and absolute request deadlines" do
    assert Ama.MultiServer.request_receive_timeout(1_000, 1_000) == {:ok, 60_000}
    assert Ama.MultiServer.request_receive_timeout(1_000, 250_000) == {:ok, 51_000}
    assert Ama.MultiServer.request_receive_timeout(1_000, 301_000) == {:error, :request_timeout}
  end
end
