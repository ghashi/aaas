class GetKeys
  # returns [ecdsa_skey, ecdsa_pkey, ntru_skey, ntru_pkey]
  def self.call
  @keys = []
    if @keys.empty?
      f = File.open("config/keys", "r")
      f.each_line do |line|
        @keys << line
      end
      f.close
    end
    @keys
  end
end
