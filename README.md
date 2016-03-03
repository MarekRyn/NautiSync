# NautiSync
Simple many-to-many messaging system

Main goals of the projects:
- simple to use
- exchanging messages between threads, processes, separate systems over multicast UDP connection
- authentication of messages by shared secret and hmac algorithm
- possibility to select any digest method for hmac
- protection against replay attack (each message have unique sequence number)
- exchanging data in OneToMany, ManyToOne, ManyToMany schemes
- each node offers send and receive function
- heart beat system included, nodes are automaticly aware about each other
- utilization of fastest available serialization module: msgpack (several times faster than cpickle)
- can send any variable or object that can be serialized by msgpack

# Use example

<pre><code>
import nautisync
data = {'aaa': '111', 'bbb': '222'}

# Create nautisync context
ns = nautisync.Context('224.0.0.1', 5000, 'SECRET PASSWORD')

# Create nautisync node 'example' in group 'gname'
node = ns.get_node("example@gname")

# Sending data to specific node
node.send('example2@gname', data)

# Sending data to any node in given group
node.send('*@gname', data)

# Sending data to specific node in any group
node.send('example2@*', data)

# Sending data to any node in any group
node.send('*@*', data)

# Receiving data
source, data = node.rxQueue.get(False)

# Checking if received data are avaiable
node.rxQueue.empty()
# return False if data are in queue

</code></pre>



