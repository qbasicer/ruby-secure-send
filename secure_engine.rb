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
		# Load the configuration file
		@config_file = arg[:configuration_file] || SecureEngine.get_config_file
		homedir = File.expand_path("~/")

		# Load our private key
		@private_key = OpenSSL::PKey::RSA.new(File.new(@config_file.pri_key).read)

		# Locate our public key file
		@public_key_file = @config_file.pub_key

		# Setup other parameters
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

		# Determine if the published keyfile is out of date
		should_write = false
		sync_key_loc = "#{@sync_dir}/#{@node_name}.pub"
		if (!File.exists? sync_key_loc) then
			should_write = true
		else
			if (File.new(@public_key_file).read != File.new(sync_key_loc).read) then
				should_write = true
			end
		end

		# Push our public key file so that the other nodes can verify us
		# Note: We're not using certificates, so we can't verify the authenticity of
		#       the key file, just that the signature matches the public key
		if (should_write) then
			f = File.open(sync_key_loc, "w")
			puts "Writing public-key to #{@sync_dir}/#{@node_name}.pub"
			f.write File.new(@public_key_file).read
			f.close
		end
	end

	def receive_secure_package(pubkey, input_stream, output_stream)
		start = Time.now
		unique = Digest::SHA1.hexdigest "#{Time.now}#{rand}#{@node_name}"

		header = input_stream.read(20)
		if (!header.start_with?("SECURE_SEND_PACKAGED")) then
			raise "BAD MAGIC HEADER, got #{header}, #{header.length}"
		end
		xfer_file_contents = input_stream.read(512)

		signature = input_stream.read(512)

		xfer_file_contents = @private_key.private_decrypt(xfer_file_contents)

		exchange = Configuration.new
		exchange.load_string(xfer_file_contents)

		fromkey = exchange.fk
		key = Base64.decode64(exchange.kf)
		iv = Base64.decode64(exchange.iv)
		base_name = exchange.nm
		sha1 = exchange.s1

		if (!pubkey) then
			pubkey = get_key_for_dest(fromkey)
		end
		if (pubkey) then
			digest = OpenSSL::Digest::SHA256.new
			verified = pubkey.verify digest, signature, xfer_file_contents
			raise "Could not verify file contents, signature is invalid!" unless verified
		else
			$stderr.puts "[WARN] Could not locate pubkey #{fromkey}, file cannot be verified!"
		end

		cipher = OpenSSL::Cipher::AES256.new(:CBC)
		cipher.decrypt
		cipher.key = key
		cipher.iv = iv

		length = 0

		sha256 = Digest::SHA256.new
		loop do
			data = input_stream.read(256)
			break if data.nil?
			data = cipher.update(data)
			length += data.length
			sha256.update(data)
			output_stream.write(data)
		end

		data = cipher.final
		sha256.update(data)
		output_stream.write(data)

		calculated_sha1 = sha256.hexdigest

		if (calculated_sha1 != sha1) then
			raise "SHA1 HASH MISMATCH"
		end
		elapsed = Time.now - start
		puts "Decrypted verified file '#{base_name}' from '#{fromkey}'" if output_stream.class == File
		puts "Decrypted #{length}B in #{elapsed}s, #{length/elapsed} Bps" if output_stream.class == File
	end

	def generate_secure_package(dest_key, base_name, data_stream, output_stream)
		start = Time.now
		unique = Digest::SHA1.hexdigest "#{base_name}#{Time.now}#{rand}#{@node_name}"

		data = data_stream.read(256)
		if (data.nil?) then
			raise "READ FAULT"
		end

		# Setup symmetric cipher
		cipher = OpenSSL::Cipher::AES256.new(:CBC)
		cipher.encrypt
		key = Base64.encode64(cipher.random_key).chomp
		iv = Base64.encode64(cipher.random_iv).chomp

		# Stream data into a temporary file
		tmpfile = "#{unique}.tmp"
		f = File.new(tmpfile, "w")

		nextMsg = (1024 * 1024)
		length = 0

		# Calculate rolling sha1
		sha256 = Digest::SHA256.new
		loop do
			data = data_stream.read(256)
			break if data.nil?
			length += data.length
			sha256.update data
			data = cipher.update(data)
			f.write(data)
		end
		d = cipher.final
		f.write(d)
		f.close

		sha1 = sha256.hexdigest

		# Generate exchange data
		xfer_file_contents = "kf=#{key}\niv=#{iv}\nnm=#{base_name}\ns1=#{sha1}\nfk=#{@node_name}.pub"

		# Generate signature on exchange data
		digest = OpenSSL::Digest::SHA256.new
		signature = @private_key.sign(digest, xfer_file_contents)

		# Encrypt exchange data
		xfer_file_contents = dest_key.public_encrypt(xfer_file_contents)

		# Magic header
		magic = "SECURE_SEND_PACKAGED"

		# Write our magic, exchange data, and signature to the top of the file
		output_stream.write(magic)
		output_stream.write(xfer_file_contents)
		output_stream.write(signature)

		# Open encrypted transfer file and append it
		f = File.new(tmpfile, "r")
		loop do
			data = f.read(256)
			break if data.nil?
			output_stream.write(data)
		end
		f.close
		File.delete(tmpfile)

		elapsed = Time.now - start
		puts "Encrypted #{length}B in #{elapsed}s, #{length/elapsed} Bps" if output_stream.class == File
	end

	def secure_send(dest, file)
		# Generate a fairly unique and random SHA1 hash for this file
		unique = Digest::SHA1.hexdigest "#{file}#{Time.now}#{rand}#{@node_name}"
		puts "Sending #{file} to #{dest}"

		if (dest.class == String) then
			dest = [dest]
		end

		start = Time.now
		
		# Prepare the symmetic algorithm to encrypt the file content
		cipher = OpenSSL::Cipher::AES256.new(:CBC)
		cipher.encrypt
		key = Base64.encode64(cipher.random_key).chomp
		iv = Base64.encode64(cipher.random_iv).chomp

		file_contents = File.new(file).read

		# Generate a SHA1 from the file, use this later to verify
		# the file hasn't been tampered with
		sha1 = Digest::SHA1.hexdigest file_contents

		# Signature is enabled for now, an option will be added later
		do_sig = true
		signature = nil
		
		# Encrypt the data file
		file_contents = cipher.update(file_contents) + cipher.final
		base_name = File.basename(file)
		xfer_name = "#{unique}.sft"

		# Write the encrypted file to the sync directory
		f = File.open("#{@sync_dir}/#{xfer_name}.tmp", "w")
		f.write file_contents
		f.close

		# Clear encrypted data from memory
		file_contents = nil

		# Prepare the exchange metadata file
		xfer_file_contents = "kf=#{key}\niv=#{iv}\nnm=#{base_name}\nfe=#{xfer_name}\ns1=#{sha1}\nfk=#{@node_name}.pub"

		# For each node that can access the data file, write an exchange file for them
		dest.each{|dest_node|
			write_secure_metadata_for(dest_node, unique, xfer_file_contents, do_sig)
		}
		start = Time.now - start

		# Rename the datafile so that the exchange files exist before the data file
		# If we wrote this first, there is a chance that it will get garbage collected
		# by a node running gc_dir
		File.rename("#{@sync_dir}/#{xfer_name}.tmp", "#{@sync_dir}/#{xfer_name}")

		puts "MD: #{dest}-#{unique}.smf, XFER: #{xfer_name}, Elapsed: #{start}"
	end

	def encrypt_for(data, pubkey)
		# Encrypt data using the pubkey file specified
		pubkey = OpenSSL::PKey::RSA.new(File.read(pubkey))
		if (pubkey == nil) then
			raise "Could not load pubkey from #{pubkey}"
		end
		pubkey.public_encrypt data
	end

	def get_key_for_dest(dest)
		remote_public_key = nil
		if (dest.end_with?(".pub")) then
			remote_public_key = "#{@sync_dir}/#{dest}"
		else
			remote_public_key = "#{@sync_dir}/#{dest}.pub"
		end
		if (!File.exists?(remote_public_key)) then
			return nil
		end
		OpenSSL::PKey::RSA.new(File.read(remote_public_key))
	end

	def write_secure_metadata_for(target_node, unique, contents, do_sig)
		dest = target_node.downcase
		remote_public_key = "#{@sync_dir}/#{dest}.pub"
		if (!File.exists?(remote_public_key)) then
			raise "Remote #{dest} doesn't have a key at #{remote_public_key}"
		end
		f = File.open("#{@sync_dir}/#{dest}-#{unique}.smf", "w")

		# Encrypt and encode the exchange data
		encoded = Base64.encode64(encrypt_for(contents, remote_public_key)).split("\n").join("")
		encoded = "contents=#{encoded}"

		if (do_sig) then
			digest = OpenSSL::Digest::SHA256.new
			# If we are expected to provide a signature for the content, 
			# generate a signture using our private key
			signature = @private_key.sign(digest, contents)
			signature = Base64.encode64(signature).split("\n").join("")
			# And add it (encoded) to the exchange file
			contents = "#{encoded}\nsignature=#{signature}"
		else
			contents = encoded
		end
		f.write(contents)
		f.close
	end

	def scan_incoming
		entries = Dir.entries(@sync_dir)
		entries.each{|entry|
			# Search for all files named like <node>-<sha1>.smf (Secure Metadata File)
			if (entry.start_with?(@node_name) && entry.end_with?(".smf")) then
				start = Time.now
				unique = Digest::SHA1.hexdigest "#{entry}#{Time.now}"
				xfer_file_contents = File.new("#{@sync_dir}/#{entry}").read

				# Read the exchange contents, for now there's two values to be read:
				#  contents - Base64 encoded encrypted exchange data containing the symmetric decryption data for the data file
				#  signature - Base64 encoded signature of the exchange data
				exchange = Configuration.new
				exchange.load_string(xfer_file_contents)
				signature = Base64.decode64(exchange.signature)
				# Decode the exchange data
				xfer_file_contents = Base64.decode64(exchange.contents)

				begin
					# Decrypt the exchange data
					xfer_file_contents = @private_key.private_decrypt(xfer_file_contents)
				rescue OpenSSL::PKey::RSAError=>e
					puts "ERROR DECRYPTING #{entry}, #{e.class} - #{e.message}"
					puts "\t#{e.backtrace.join("\n\t")}"
					next
				end


				#Verify all the expected parameters are there
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

				# Checking
				raise "Missing key" if key.nil?
				raise "Missing iv" if iv.nil?
				raise "Missing name" if name.nil?
				raise "Missing file" if file.nil?
				raise "Missing sha1" if tsha1.nil?

				# If the matching datafile is present, we can actually finalize the process
				if (File.exists?("#{@sync_dir}/#{file}")) then
					puts "Receiving file #{@inbox}/#{name}"

					# Read the encrypted data
					file_contents = File.new("#{@sync_dir}/#{file}").read

					# Move the exchange file
					File.rename("#{@sync_dir}/#{entry}", "#{@tmpdir}/#{unique}.smf")

					# Setup and decrypt the data file
					cipher = OpenSSL::Cipher::AES256.new(:CBC)
					cipher.decrypt
					cipher.key = key
					cipher.iv = iv
					file_contents = cipher.update(file_contents) + cipher.final

					# Verify the file has the correct hash, as determined by the exchange data
					sha1 = Digest::SHA1.hexdigest file_contents
					if (tsha1 != sha1) then
						raise "Calculated sha1 #{sha1} does not match expected sha1 #{tsha1}"
					end

					# If we have a signature, verify it
					# It requires that we actually have the pubkey for the sender
					if (fromkey != nil && signature != nil) then
						pubkey = OpenSSL::PKey::RSA.new(File.read("#{@sync_dir}/#{fromkey}"))
						if (pubkey) then
							digest = OpenSSL::Digest::SHA256.new
							verified = pubkey.verify digest, signature, xfer_file_contents
							if (!verified) then
								# If we can't verify, bail.
								raise "[FATAL] Could not verify sender key, signatures do not match"
							end
						else
							puts "[ERROR] Could not load pubkey #{@sync_dir}/#{fromkey}, cannot verify sender"
						end
					else
						puts "[WARN] Sender didn't sign data, cannot verify sender"
					end

					# Write the incoming file into the inbox
					f = File.open("#{@inbox}/#{name}", "w")
					f.write file_contents
					f.close

					# Delete the metadata exchange file
					File.delete "#{@tmpdir}/#{unique}.smf"
					start = Time.now - start
					
					puts "Received file #{@inbox}/#{name} - #{sha1} @ #{Time.now} - #{start}s - verified: #{verified}"
					
					# Clean up
					gc_dir
				end
			end
		}
	end

	def rx_server
		# In a threaded loop, continously check for incoming data
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
		# Scan the directory looking for unused data files not referenced by anybody.
		# Multiple metadata exchange files can point to a single data file.
		# The filename of a datafile includes a sha1 hash that's unique (enough)
		# If we looking for that in a file named like:
		#    <foo>-<sha1>.smf
		# Then the file is still referenced
		# If nobody references it, we can delete it
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
			end
		}
	end

	# Get the default config file
	def self.get_config_file
		homedir = File.expand_path("~/")
		self_config = "#{homedir}/.secure/config"
		config = Configuration.new
		config.load_file self_config
		config
	end

	# Perform startup
	def self.ensure_keys
		homedir = File.expand_path("~/")

		# Check to see if the config file exists
		if (!File.exists?("#{homedir}/.secure/config")) then

			# If it doesn't, check to see if the dir exists
			if (!Dir.exists?("#{homedir}/.secure")) then
				# If it doesn't, create it
				Dir.mkdir "#{homedir}/.secure"
			end

			# Stub out a configuration file
			f = File.open(self_config, "w")
			f.puts "name=NODE_NAME_HERE"
			f.puts "pub_key=#{homedir}/.secure/self.pub"
			f.puts "pri_key=#{homedir}/.secure/self.key"
			f.puts "sync_dir=#{homedir}/global/secure"
			f.puts "inbox=#{homedir}/inbox"
			f.close

			# Generate a key
			puts "Generating keys"
			sys1_pri = OpenSSL::PKey::RSA.generate(4096)
			sys1_pub = sys1_pri.public_key

			# Write them out
			f = File.open("#{homedir}/.secure/self.pub", "w")
			f.write sys1_pub
			f.close

			f = File.open("#{homedir}/.secure/self.key", "w")
			f.write sys1_pri
			f.close

			# Notify the user they need to configure us
			raise "No configuration present, please modify #{self_config}"
		end

		# Check to see if the configuration is valid
		config = Configuration.new
		config.load_file "#{homedir}/.secure/config"

		# Verify the node name isn't the default value
		if (config.name.nil? || config.name == "NODE_NAME_HERE") then
			raise "Node name hasn't been properly configured, please modify #{homedir}/.secure/config"
		end

		# Verify that the keyfiles all exist
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
