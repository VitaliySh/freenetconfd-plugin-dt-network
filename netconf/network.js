var netconf_client = require('./core/netconf_client')

var client = netconf_client.create(function(error)
{
	if (error)
	{
		console.error(error)
		process.exit(1)
	}

	var xml

	xml = 'TODO'

	client.send(xml, function(error, reply)
	{
		if (error)
		{
			console.error(error)
			process.exit(1)
		}

		client.send_close(function(error, reply)
		{
			if (error)
			{
				console.error(error)
				process.exit(1)
			}
			else
			{
				process.exit(0)
			}

		})
	})

})

client.on('rpc-reply', function(reply)
{
})

client.on('error', function(error)
{
	console.error(error)
	process.exit(1)
})

client.on('end', function(error)
{
})
