require_relative '../certificate_wrapper/certificate_wrapper'

namespace :app do
  desc "This task erases the database and creates new pair of keys"
  task :restart do
    Rake::Task['db:reset'].invoke
    p "Users detroyed!"

    ecdsa_keys = CertificateWrapper.ecdsa_keygen()
    ntru_keys = CertificateWrapper.ntru_keygen()
    out_file = File.new("config/keys", "w")
    out_file.puts(ecdsa_keys[0])
    out_file.puts(ecdsa_keys[1])
    out_file.puts(ntru_keys[0])
    out_file.puts(ntru_keys[1])
    out_file.close
    p "New keys (NTRU, ECDSA) generated!"
  end
end
