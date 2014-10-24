json.array!(@users) do |user|
  json.extract! user, :id, :name, :token_count, :pkey
  json.url user_url(user, format: :json)
end
