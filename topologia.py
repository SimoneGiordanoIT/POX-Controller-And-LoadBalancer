from mininet.topo import Topo

class MyTopo( Topo ):

	def __init__( self ):

		Topo.__init__( self )

		h1=self.addHost('h1', ip='10.0.0.101/8', mac='00:00:00:00:00:01', defaultRoute='via 10.0.0.1')
		h2=self.addHost('h2', ip='10.0.0.102/8', mac='00:00:00:00:00:02', defaultRoute='via 10.0.0.1')
		h3=self.addHost('h3', ip='10.0.0.103/8', mac='00:00:00:00:00:03', defaultRoute='via 10.0.0.1')
		h4=self.addHost('h4', ip='10.0.0.104/8', mac='00:00:00:00:00:04', defaultRoute='via 10.0.0.1')

		c1=self.addHost('c1', ip='79.12.1.10/24', mac='00:00:00:00:00:05', defaultRoute='via 79.12.1.1')
		c2=self.addHost('c2', ip='79.12.2.10/24', mac='00:00:00:00:00:06', defaultRoute='via 79.12.2.1')
		c3=self.addHost('c3', ip='79.12.3.10/24', mac='00:00:00:00:00:07', defaultRoute='via 79.12.3.1')
		c4=self.addHost('c4', ip='79.12.4.10/24', mac='00:00:00:00:00:08', defaultRoute='via 79.12.4.1')

		s1=self.addSwitch('s1')

		self.addLink(s1, h1)
		self.addLink(s1, h2)
		self.addLink(s1, h3)
		self.addLink(s1, h4)

		self.addLink(s1, c1)
		self.addLink(s1, c2)
		self.addLink(s1, c3)
		self.addLink(s1, c4)


	


topos = { 'mytopo': ( lambda: MyTopo() ) }
