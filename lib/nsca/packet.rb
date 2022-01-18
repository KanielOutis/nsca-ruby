module NSCA
	class Packet
		class CSC32CheckFailed <Exception
		end
		class VersionCheckFailed <Exception
		end

		def self.versions version = nil
			@@versions ||= {}
			version ? @@versions[version] : @@versions
		end

		def self.register_version( version, klass) versions[version] = klass end

		# @param [Time,Integer,nil] timestamp Checked at this time
		# @param [0..3] return_code `NSCA::ReturnCode`
		# @param [String(length<64),nil] hostname If nil, local hostname will be used.
		#                                         Must be known by Nagios.
		# @param [String(length<128)] service Name of Service. Must be known by Nagios.
		# @param [String(length<512)] status Status-line inclusive optional Performance Data.
		def initialize timestamp, return_code, hostname, service, status
			@timestamp, @return_code, @hostname, @service, @status =
				Time.at( timestamp.to_f), return_code, hostname, service, status
		end

		attr_accessor :timestamp, :return_code, :hostname, :service, :status
	end

	class PacketV3 < Packet
		NAGIOS_VERSION = 2.7
		PACKET_VERSION = 3
		END_OF_TRANSMISSION = ?\x0a
		HOSTNAME_LENGTH = 64
		SERVICE_LENGTH = 128
		PLUGIN_OUTPUT_LENGTH = 512

		# these line describes the data package:
		# typedef struct data_packet_struct{
		#   int16_t   packet_version;
		#   /* two padding bytes (because aligning): xx */
		#   u_int32_t crc32_value;
		#   u_int32_t timestamp;
		#   int16_t   return_code;
		#   char      host_name[MAX_HOSTNAME_LENGTH];
		#   char      svc_description[MAX_DESCRIPTION_LENGTH];
		#   char      plugin_output[MAX_PLUGINOUTPUT_LENGTH];
		#   /* two extra padding-xx, too. */
		# }data_packet;
		PACK_STRING = "s> xx L> L> s> A#{HOSTNAME_LENGTH} A#{SERVICE_LENGTH} A#{PLUGIN_OUTPUT_LENGTH} xx"
		PACK_LENGTH = 2+2+4+4+2+HOSTNAME_LENGTH+SERVICE_LENGTH+PLUGIN_OUTPUT_LENGTH+2
		register_version PACKET_VERSION, self

		# Builds a check-result-line for NSCA.
		#
		# Will be terminated by end-of-terminate.
		def build slf = nil
			cl = (slf || self).class
			entry = [
				cl::PACKET_VERSION,
				0, # crc32 (unknown yet)
				(timestamp || Time.now).to_i,
				return_code.to_i,
				NSCA::str2cstr_rand_padding( hostname || `hostname -f`, cl::HOSTNAME_LENGTH),
				NSCA::str2cstr_rand_padding( service, cl::SERVICE_LENGTH),
				NSCA::str2cstr_rand_padding( status, cl::PLUGIN_OUTPUT_LENGTH) # incl perfdata
			]
			# generate crc32 and put it at entry[2...6]
			entry[1] = NSCA::crc32 entry.pack( cl::PACK_STRING)
			entry = entry.pack cl::PACK_STRING
			entry
		end

		def self.parse entry, no_verification_checks = nil
			entry = entry.to_s.dup
			ver, crc32sum, *x = entry.unpack( PACK_STRING)
			x[2] = NSCA::cstr2str x[2]
			x[3] = NSCA::cstr2str x[3]
			x[4] = NSCA::cstr2str x[4]
			raise VersionCheckFailed, "Packet version 3 expected. (recv: #{ver})" \
				unless no_verification_checks or 3 == ver
			entry[4..7] = ?\x00*4
			crc32 = NSCA::crc32 entry
			raise CSC32CheckFailed, "crc32-check failed. packet seems to be broken: #{crc32sum.inspect} != #{crc32.inspect}" \
				unless no_verification_checks or crc32sum == crc32
			new *x
		end
	end

	class PacketV3__2_9 < PacketV3
		NAGIOS_VERSION = 2.7
		PACKET_VERSION = 3
		END_OF_TRANSMISSION = ?\x0a
		PLUGIN_OUTPUT_LENGTH = 4096
		HOSTNAME_LENGTH = 64
		SERVICE_LENGTH = 128
		PACK_STRING = "s> xx L> L> s> A#{HOSTNAME_LENGTH} A#{SERVICE_LENGTH} A#{PLUGIN_OUTPUT_LENGTH} xx"
		PACK_LENGTH = 2+2+4+4+2+HOSTNAME_LENGTH+SERVICE_LENGTH+PLUGIN_OUTPUT_LENGTH+2
	end
end
