require 'openssl'
require 'base64'
require 'singleton'

unless Dir.respond_to?(:exists?)
	class Dir
		def self.exists?(path)
			return File.exists?(path)
		end
	end
end

class Configuration
	def initialize
		@backing_hash = {}
	end

	def load_file(file)
		@backing_hash = {}
		contents = File.new(file).read.split("\n")
		contents.each{|line|
			if (line.include?("=")) then
				idx = line.index "="
				var = line[0..idx-1].chomp
				val = line[idx+1..-1].chomp
				write_value(var, val)
			end
		}
	end

	def load_string(data)
		@backing_hash = {}
		data.split("\n").each{|line|
			if (line.include?("=")) then
				idx = line.index "="
				var = line[0..idx-1].chomp
				val = line[idx+1..-1].chomp
				write_value(var, val)
			end
		}
	end

	def save_file(file)
		f = File.open(file, "w")
		@backing_hash.each{|k,v|
			f.puts "#{k}=#{v}"
		}
		f.close
	end

	def file_exists?(value)
		val = @backing_hash[value]
		return false if val.nil?
		File.exists? val
	end

	def dir_exists?(value)
		val = @backing_hash[value]
		return false if val.nil?
		Dir.exists? val
	end

	def include?(value)
		@backing_hash.include? value
	end

	def write_value(value, variable)
		@backing_hash[value] = variable
	end

	def read_value(value)
		v = @backing_hash[value]
		v
	end

	def keys
		@backing_hash.keys
	end

	def method_missing(sym, *args, &block)
		if (sym.to_s == "[]") then
			return read_value(args[0])
		elsif (sym.to_s.end_with?("=")) then
			write_value(args[0], args[1])
		else
			read_value(sym.to_s)
		end
	end
end


class SecureEngine
	def initialize(arg)
		@config_file = arg[:configuration_file] || SecureEngine.get_config_file
		homedir = File.expand_path("~/")

		puts "Loading private key #{@config_file.pri_key}"
		@private_key = OpenSSL::PKey::RSA.new(File.new(@config_file.pri_key).read)
		@public_key_file = @config_file.pub_key
		@node_name = @config_file["name"]
		@inbox = @config_file.inbox
		@sync_dir = @config_file.sync_dir
		@tmpdir = @config_file.tmpdir || "#{homedir}/.secure/tmp"
		if (@private_key == nil) then
			raise "Private key not specified or invalid"
		elsif (@public_key_file == nil) then
			raise "Public key file not specified or invalid"
		elsif (@node_name == "NODE_NAME_HERE") then
			raise "Invalid node name"
		elsif (@inbox == nil) then
			raise "Invalid inbox"
		elsif (@sync_dir == nil) then
			raise "Invalid sync_dir"
		end
		if (!Dir.exists?(@tmpdir)) then
			Dir.mkdir @tmpdir
		end

		should_write = false
		sync_key_loc = "#{@sync_dir}/#{@node_name}.pub"
		if (!File.exists? sync_key_loc) then
			should_write = true
		else
			if (File.new(@public_key_file).read != File.new(sync_key_loc).read) then
				should_write = true
			end
		end

		if (should_write) then
			f = File.open(sync_key_loc, "w")
			puts "Writing public-key to #{@sync_dir}/#{@node_name}.pub"
			f.write File.new(@public_key_file).read
			f.close
		end
	end

	def secure_send(dest, file)
		unique = Digest::SHA1.hexdigest "#{file}#{Time.now}#{rand}#{@node_name}"
		puts "Sending #{file} to #{dest}"

		if (dest.class == String) then
			dest = [dest]
		end

		start = Time.now
		
		cipher = OpenSSL::Cipher::AES256.new(:CBC)
		cipher.encrypt
		key = Base64.encode64(cipher.random_key).chomp
		iv = Base64.encode64(cipher.random_iv).chomp

		file_contents = File.new(file).read

		sha1 = Digest::SHA1.hexdigest file_contents

		do_sig = true
		signature = nil
		
		file_contents = cipher.update(file_contents) + cipher.final
		base_name = File.basename(file)
		xfer_name = "#{unique}.sft"
		f = File.open("#{@sync_dir}/#{xfer_name}", "w")
		f.write file_contents
		f.close

		# Clear encrypted data from memory
		file_contents = nil

		xfer_file_contents = "kf=#{key}\niv=#{iv}\nnm=#{base_name}\nfe=#{xfer_name}\ns1=#{sha1}\nfk=#{@node_name}.pub"
		if (xfer_file_contents.length > 255) then
			puts "[WARN] Metadata exchange file is large (#{xfer_file_contents.length})"
		end
		dest.each{|dest_node|
			write_secure_metadata_for(dest_node, unique, xfer_file_contents, do_sig)
		}

		start = Time.now - start
		puts "MD: #{dest}-#{unique}.smf, XFER: #{xfer_name}, Elapsed: #{start}"
	end

	def encrypt_for(data, pubkey)
		pubkey = OpenSSL::PKey::RSA.new(File.read(pubkey))
		if (pubkey == nil) then
			raise "Could not load pubkey from #{pubkey}"
		end
		pubkey.public_encrypt data
	end

	def write_secure_metadata_for(target_node, unique, contents, do_sig)
		

		dest = target_node.downcase
		remote_public_key = "#{@sync_dir}/#{dest}.pub"
		if (!File.exists?(remote_public_key)) then
			raise "Remote #{dest} doesn't have a key at #{remote_public_key}"
		else
			puts "Writing SecureMetadataFile exchange using #{remote_public_key}"
		end
		f = File.open("#{@sync_dir}/#{dest}-#{unique}.smf", "w")

		if (do_sig) then
			digest = OpenSSL::Digest::SHA256.new
			signature = @private_key.sign(digest, contents)

			digest = OpenSSL::Digest::SHA256.new
			valid = @private_key.public_key.verify(digest, signature, contents)
			if (!valid) then
				raise "FAULT"
			else
				puts "SIGNATURE VALIDATION OKAY"
			end
			contents = encrypt_for(contents, remote_public_key)
			encoded = Base64.encode64(contents).split("\n").join("")
			signature = Base64.encode64(signature).split("\n").join("")
			contents = "SIGNED_METADATA_EXCHANGE\ncontents=#{encoded}\nsignature=#{signature}"
		else
			contents = encrypt_for(contents, remote_public_key)
		end
		f.write(contents)
		f.close
	end

	def scan_incoming
		entries = Dir.entries(@sync_dir)
		entries.each{|entry|
			if (entry.start_with?(@node_name) && entry.end_with?(".smf")) then
				start = Time.now
				unique = Digest::SHA1.hexdigest "#{entry}#{Time.now}"
											
				xfer_file_contents = File.new("#{@sync_dir}/#{entry}").read
				signature = nil

				if (xfer_file_contents.include?("SIGNED_METADATA_EXCHANGE")) then
					exchange = Configuration.new
					exchange.load_string(xfer_file_contents)

					contents = exchange.contents
					signature = Base64.decode64 exchange.signature
					xfer_file_contents = Base64.decode64 contents
				end

				begin
					xfer_file_contents = @private_key.private_decrypt(xfer_file_contents)
				rescue OpenSSL::PKey::RSAError=>e
					puts "ERROR DECRYPTING #{entry}, #{e.class} - #{e.message}"
					puts "\t#{e.backtrace.join("\n\t")}"
					next
				end

				key = nil
				iv = nil
				name = nil
				file = nil
				tsha1 = nil
				sha1 = nil
				
				fromkey = nil
				verified = false
				xfer_file_contents.split("\n").each{|line|
					if (line.include?("=")) then
						idx = line.index("=")
						var = line[0..idx-1].chomp
						val = line[idx+1..-1].chomp
						if (var == "kf") then
							key = Base64.decode64 val
						elsif (var == "iv") then
							iv = Base64.decode64 val
						elsif (var == "nm") then
							name = val
						elsif (var == "fe") then
							file = val
						elsif (var == "s1") then
							tsha1 = val
						elsif (var == "sf") then
							signature_file = val
						elsif (var == "fk") then
							fromkey = val
						end
					end
				}

				raise "Missing key" if key.nil?
				raise "Missing iv" if iv.nil?
				raise "Missing name" if name.nil?
				raise "Missing file" if file.nil?
				raise "Missing sha1" if tsha1.nil?

				if (File.exists?("#{@sync_dir}/#{file}")) then
					puts "Receiving file #{@inbox}/#{name}"

					File.rename("#{@sync_dir}/#{entry}", "#{@tmpdir}/#{unique}.smf")
					file_contents = File.new("#{@sync_dir}/#{file}").read
					cipher = OpenSSL::Cipher::AES256.new(:CBC)
					cipher.decrypt
					cipher.key = key
					cipher.iv = iv
					file_contents = cipher.update(file_contents) + cipher.final
					if (tsha1 != nil) then
						sha1 = Digest::SHA1.hexdigest file_contents
						if (tsha1 != sha1) then
							raise "Calculated sha1 #{sha1} does not match expected sha1 #{tsha1}"
						end
					end
					if (fromkey != nil && signature != nil) then
						pubkey = OpenSSL::PKey::RSA.new(File.read("#{@sync_dir}/#{fromkey}"))
						if (pubkey) then
							digest = OpenSSL::Digest::SHA256.new
							verified = pubkey.verify digest, signature, xfer_file_contents
							if (!verified) then
								raise "[FATAL] Could not verify sender key, signatures do not match"
							end
						else
							puts "[ERROR] Could not load pubkey #{@sync_dir}/#{fromkey}, cannot verify sender"
						end
					else
						puts "[WARN] Sender didn't sign data, cannot verify sender"
					end

					f = File.open("#{@inbox}/#{name}", "w")
					f.write file_contents
					f.close

					#File.delete "#{@sync_dir}/#{file}"
					File.delete "#{@tmpdir}/#{unique}.smf"
					start = Time.now - start
					
					puts "Received file #{@inbox}/#{name} - #{sha1} @ #{Time.now} - #{start}s - verified: #{verified}"
					
					gc_dir
				end
			end
		}
	end

	def rx_server
		gc_dir
		t = Thread.new{
			loop do
				scan_incoming

				sleep(5)
			end
		}

		t.join
	end

	def gc_dir
		entries = Dir.entries(@sync_dir)
		entries.each{|entry|
			if (entry.end_with?(".sft")) then
				sha1 = entry[0..entry.index(".")-1]
				to_delete = true
				entries.each{|search_entry|
					if (/.*-#{sha1}/ =~ search_entry) then
						to_delete = false
					end
				}
				if (to_delete) then
					puts "Unused data file detected, deleting #{@sync_dir}/#{entry}"
					File.delete "#{@sync_dir}/#{entry}"
				end
			elsif (entry.end_with?(".ssf")) then
				sha1 = entry[0..entry.index(".")-1]
				to_delete = true
				entries.each{|search_entry|
					if (/.*-#{sha1}/ =~ search_entry) then
						to_delete = false
					end
				}
				if (to_delete) then
					puts "Unused signature file detected, deleting #{@sync_dir}/#{entry}"
					File.delete "#{@sync_dir}/#{entry}"
				end
			end
		}
	end

	def generate_cert
		root_key = OpenSSL::PKey::RSA.new 2048 # the CA's public/private key
		root_ca = OpenSSL::X509::Certificate.new
		root_ca.version = 2 # cf. RFC 5280 - to make it a "v3" certificate
		root_ca.serial = 1
		root_ca.subject = OpenSSL::X509::Name.parse "/DC=org/DC=ruby-lang/CN=Ruby CA"
		root_ca.issuer = root_ca.subject # root CA's are "self-signed"
		root_ca.public_key = root_key.public_key
		root_ca.not_before = Time.now
		root_ca.not_after = root_ca.not_before + 2 * 365 * 24 * 60 * 60 # 2 years validity
		ef = OpenSSL::X509::ExtensionFactory.new
		ef.subject_certificate = root_ca
		ef.issuer_certificate = root_ca
		root_ca.add_extension(ef.create_extension("basicConstraints","CA:TRUE",true))
		root_ca.add_extension(ef.create_extension("keyUsage","keyCertSign, cRLSign", true))
		root_ca.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
		root_ca.add_extension(ef.create_extension("authorityKeyIdentifier","keyid:always",false))
		root_ca.sign(root_key, OpenSSL::Digest::SHA256.new)

		key = OpenSSL::PKey::RSA.new 2048
		cert = OpenSSL::X509::Certificate.new
		cert.version = 2
		cert.serial = 2
		cert.subject = OpenSSL::X509::Name.parse "/DC=org/DC=ruby-lang/CN=Ruby certificate"
		cert.issuer = root_ca.subject # root CA is the issuer
		cert.public_key = key.public_key
		cert.not_before = Time.now
		cert.not_after = cert.not_before + 1 * 365 * 24 * 60 * 60 # 1 years validity
		ef = OpenSSL::X509::ExtensionFactory.new
		ef.subject_certificate = cert
		ef.issuer_certificate = root_ca
		cert.add_extension(ef.create_extension("keyUsage","digitalSignature", true))
		cert.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
		out = cert.sign(root_key, OpenSSL::Digest::SHA256.new)
		puts out
		puts out.class
		out
	end

	def self.get_config_file
		homedir = File.expand_path("~/")
		self_config = "#{homedir}/.secure/config"
		config = Configuration.new
		config.load_file self_config
		config
	end

	def self.ensure_keys
		homedir = File.expand_path("~/")

		if (!File.exists?("#{homedir}/.secure/config")) then

			if (!Dir.exists?("#{homedir}/.secure")) then
				Dir.mkdir "#{homedir}/.secure"
			end

			f = File.open(self_config, "w")
			f.puts "name=NODE_NAME_HERE"
			f.puts "pub_key=#{homedir}/.secure/self.pub"
			f.puts "pri_key=#{homedir}/.secure/self.key"
			f.puts "sync_dir=#{homedir}/global/secure"
			f.puts "inbox=#{homedir}/inbox"
			f.close

			puts "Generating keys"
			sys1_pri = OpenSSL::PKey::RSA.generate( 4096 )
			sys1_pub = sys1_pri.public_key

			f = File.open("#{homedir}/.secure/self.pub", "w")
			f.write sys1_pub
			f.close

			f = File.open("#{homedir}/.secure/self.key", "w")
			f.write sys1_pri
			f.close



			raise "No configuration present, please modify #{self_config}"
		end

		config = Configuration.new
		config.load_file "#{homedir}/.secure/config"

		if (config.name.nil? || config.name == "NODE_NAME_HERE") then
			raise "Node name hasn't been properly configured, please modify #{homedir}/.secure/config"
		end

		if (!config.file_exists? "pub_key") then
			raise "No valid public key specified in #{homedir}/.secure/config, #{Configuration.keys}"
		elsif (!config.file_exists? "pri_key") then
			raise "No valid private key specified in #{homedir}/.secure/config"
		elsif (!config.dir_exists? "sync_dir") then
			raise "No valid sync_dir specified in #{homedir}/.secure/config"
		elsif (!config.file_exists? "inbox") then
			raise "No valid inbox specified in #{homedir}/.secure/config"
		end
	end
end

SecureEngine.ensure_keys
