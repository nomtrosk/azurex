defmodule Azurex.Authorization.ManagedIdentity do
  require Logger
  alias Azurex.Blob.Config

  @ets_table_name :managed_identity_bearer_token_cache
  @cache_key "azurex_bearer_token"
  @cache_expiry_margin_seconds 10

  @doc """
  Fetches a bearer token and adds it to the request headers.
  In case fetching the token fails, it logs an error and returns "No token"
  which will fail the real request.
  """
  @spec add_bearer_token(HTTPoison.Request.t(), binary(), binary(), binary()) ::
          HTTPoison.Request.t()
  def add_bearer_token(%HTTPoison.Request{} = request, client_id, tenant_id, identity_token) do
    bearer_token = fetch_bearer_token_cached(client_id, tenant_id, identity_token)
    authorization = {"Authorization", "Bearer #{bearer_token}"}

    headers = [authorization | request.headers]
    struct(request, headers: headers)
  end

  defp fetch_bearer_token_cached(client_id, tenant_id, identity_token) do
    if :ets.info(@ets_table_name) == :undefined do
      :ets.new(@ets_table_name, [:named_table, :public])
    end

    system_os_time = System.os_time(:second)

    case :ets.lookup(@ets_table_name, @cache_key) do
      [{@cache_key, token, expiry}] when expiry > system_os_time -> token
      _ -> refresh_bearer_token_cache(client_id, tenant_id, identity_token)
    end
  end

  defp refresh_bearer_token_cache(client_id, tenant_id, identity_token) do
    case fetch_bearer_token(client_id, tenant_id, identity_token) do
      {:ok, %{"access_token" => token, "expires_in" => expires_in}} ->
        expiry = System.os_time(:second) + expires_in - @cache_expiry_margin_seconds
        :ets.insert(@ets_table_name, {@cache_key, token, expiry})
        token

      :error ->
        "No token"
    end
  end

  def fetch_bearer_token(client_id, tenant_id, identity_token) do
    identity_token = File.read!(identity_token)

    request =
      %HTTPoison.Request{
        method: :post,
        url: "#{Config.get_auth_url()}/#{tenant_id}/oauth2/v2.0/token",
        body:
          URI.encode_query(%{
            "client_id" => client_id,
            "grant_type" => "client_credentials",
            "scope" => "https://storage.azure.com/.default",
            "client_assertion" => identity_token,
            "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
          }),
        headers: [
          {"content-type", "application/x-www-form-urlencoded"}
        ]
      }

    case HTTPoison.request(request) do
      {:ok, %HTTPoison.Response{status_code: 200, body: body}} ->
        {:ok, Jason.decode!(body)}

      {:ok, %HTTPoison.Response{status_code: sc, body: body}} ->
        Logger.error("Failed to fetch bearer token. Reason: #{sc}: #{body}")
        :error

      {:error, %HTTPoison.Error{reason: reason}} ->
        Logger.error("Failed to fetch bearer token. Reason: #{reason}")
        :error
    end
  end
end
