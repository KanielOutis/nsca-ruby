module NSCA
	class Server
		include Enumerable

		attr_reader :iv_key, :server, :packet_version, :password, :xor_iv_key, :xor_password
		def initialize *args
			opts = {}
			opts = args.pop.dup  if args.last.is_a? Hash
			opts[:host] ||= opts[:hostname]
			opts[:serv] ||= opts[:server]
			opts[:pass] ||= opts[:password]

			case args[0]
			when Integer
				opts[:port] = args[0]
				opts[:host] ||= args[1]
			when IO
				opts[:serv] = args[0]
			end

			@packet_version = opts[:packet_version] || PacketV3
			@iv_key = (opts[:iv_key] || SecureRandom.random_bytes( 128)).to_s
			raise ArgumentError, "Key must be 128 bytes long"  unless 128 == @iv_key.length
			@password = opts[:pass].to_s
			@server = if opts[:serv].is_a?( TCPServer) or opts[:serv].is_a?( UNIXServer)
					opts[:serv]
				elsif opts[:port].is_a? Integer
					TCPServer.new *[opts[:host], opts[:port]].compact
				else
					raise ArgumentError, "Server or port-number expected"
				end
		end

		def accept() Connection.new @server.accept, self end
		def close() @server.close end

		def each &block
			return Enumerator.new( self)  unless block_given?
			while conn = accept
				yield conn
			end
		end

		class Connection
			include Enumerable

			def initialize socket, server
				@socket, @server = socket, server
				@iv_key, @password = server.iv_key, server.password
				@packet_version = server.packet_version
				@packet_length = @packet_version::PACK_LENGTH
				@socket.write [@iv_key, Time.now.to_i].pack( 'a* L>')
				@xor_password = NSCA::Helper.xor_stream @password 
				@xor_iv_key = NSCA::Helper.xor_stream @iv_key
			end

			def fetch
				iv_key = NSCA::Helper.xor_stream @iv_key
				password = NSCA::Helper.xor_stream @password
				packet_version = iv_key[ password[ read PacketV3::PACKET_VERSION]]
				v = packet_version.unpack( 's>').first
				case v
				when 3
					data = packet_version + iv_key[ password[ read( PacketV3::PACK_LENGTH - PacketV3::PACKET_VERSION)]]
					begin
						return PacketV3.parse( data)
					rescue NSCA::Packet::CSC32CheckFailed
						x = read( PacketV3__2_9::PACK_LENGTH - data.length)
						raise  if x.nil?
						return PacketV3__2_9.parse( data + iv_key[ password[ x]])
					end
				else raise "Unknown Version #{v.inspect}"
				end
			end

			def each &block
				return Enumerator.new( self)  unless block_given?
				yield fetch  until eof?
			end

			def eof?() @socket.eof? end
			def read( len = nil)  @socket.read( len || @packet_length) end
			def close() @socket.close end
		end
	end
end
