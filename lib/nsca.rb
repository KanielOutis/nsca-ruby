require 'socket'
require 'enum'
require 'timeout'
require 'benchmark'
require 'securerandom'

module NSCA
	class ReturnCode <Enum
		start_at 0
		enum %w[OK WARNING CRITICAL UNKNOWN]
	end
	
	module Helper
		class <<self
			def class_name_gen label
				clname = label.gsub( /\W+/, '_').sub /^[0-9_]+/, ''
				return nil  if clname.empty?
				clname[0] = clname[0].upcase
				clname.to_sym
			end

			def xor_stream key
				key = case key
				when Array  then key
				when String then key.bytes.to_a
				when Enumerable then key.to_a
				end
				return lambda{|x|x}  if [nil, '', []].include? key
				length = key.length
				i = 0
				lambda do |str|
					r = ''
					str.bytes.each_with_index do |c, j|
						r[j] = (c ^ key[i]).chr
						i = (i + 1) % length
					end
					r
				end
			end

			def crc32_stream
				sum = 0xFFFFFFFF
				lambda do |str|
					sum = str.bytes.inject sum do |r, b|
						8.times.inject( r^b) {|r,_i| (r>>1) ^ (0xEDB88320 * (r&1)) }
					end  if str
					sum ^ 0xFFFFFFFF
				end
			end
		end
	end

	class <<self
		def destinations()  @destinations ||= []  end

		def send *results
			NSCA.destinations.each {|server| server.send *results }
			self
		end

		def xor key, msg = nil, key_a = nil
			NSCA::Helper.xor_stream( key_a || key)[ msg]
		end

		def crc32 msg
			NSCA::Helper.crc32_stream[ msg]
		end

		# Builds a null terminated, null padded string of length maxlen
		def str2cstr str, maxlen = nil
			str = str.to_s
			str = str.to_s[0..(maxlen-2)]  if maxlen
			"#{str}\x00"
		end
		def rand_padding( str, maxlen) str + SecureRandom.random_bytes( maxlen - str.length) end
		def str2cstr_rand_padding( str, maxlen = nil) rand_padding str2cstr( str, maxlen), maxlen end
		def str2nstr str, maxlen = nil
			str = str.to_s.gsub ' ', "\x00"
			"#{str} "
		end
		def str2nstr_rand_padding( str, maxlen = nil) rand_padding str2nstr( str, maxlen), maxlen end
		def cstr2str( str, maxlen = nil)  str[ 0, str.index( ?\0) || ((maxlen||str.length+1)-1)]  end
		def nstr2str( str, maxlen = nil)  str[ 0, str.index( ' ') || ((maxlen||str.length+1)-1)].gsub( "\x00", ' ')  end
	end
end

require 'nsca/packet'
require 'nsca/server'
require 'nsca/client'
require 'nsca/check'
