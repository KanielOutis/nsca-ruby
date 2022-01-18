require 'pathname'
$: << Pathname.new( __FILE__).dirname.join( '..', 'lib').to_s

module NSCA
	def self.dummy_server *args
		Dir[ Pathname.new( __FILE__).dirname.join( '..', 'lib', '**').to_s].each_entry do |l|
			load l  if /\.rb$/ =~ l
		end
		serv = NSCA::Server.new *args
		sock = serv.accept
		sock.to_a
	ensure
		sock.close  if sock
		serv.close  if serv
	end
end
