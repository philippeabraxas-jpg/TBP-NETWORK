// DEV-TEST site on Azure: the three machines of deploy/dev-test/site.md on one private network.
//
//   M1 the cell (10.20.0.10)   M2 an application server (10.20.0.11)   M3 an agent (10.20.0.12)
//
// NOT FOR PRODUCTION. It creates: one virtual network, one firewall (network security group), three Debian 12
// virtual machines with a public address each, and nothing else. No password login, no data disk, no identity.
// The firewall lets in: ssh (22) from ONE address that you give, and — between the three machines only — the three
// ports of the test (8443 the cell, 9000 the application, 9100 the live console). Everything else is refused, from
// the Internet and between the machines. The page of the console is reached through an ssh tunnel (azure.md).
//
// Step by step: azure.md. Delete everything afterwards by deleting the resource group.

targetScope = 'resourceGroup'

@description('YOUR public IPv4 address, one address (for example 203.0.113.7). The only address allowed to open ssh.')
@minLength(7)
@maxLength(15)
param adminIp string

@description('The public half of your ssh key: the whole line, starting with ssh-ed25519 or ssh-rsa.')
param sshPublicKey string

@description('Where to create everything. By default: the region of the resource group.')
param location string = resourceGroup().location

@description('Machine size. 2 CPUs and 4 GB is a starting point: nobody has measured the smallest size that works.')
param vmSize string = 'Standard_B2s'

@description('The login on the three machines (Azure forbids "admin" and "root").')
param adminUsername string = 'tbp'

var subnetPrefix = '10.20.0.0/24'
var machines = [
  { name: 'm1', ip: '10.20.0.10', role: 'the cell' }
  { name: 'm2', ip: '10.20.0.11', role: 'the application server' }
  { name: 'm3', ip: '10.20.0.12', role: 'the agent' }
]
var tags = {
  purpose: 'tbp-devtest'
  notForProduction: 'true'
}

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: 'tbp-devtest-nsg'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'allow-ssh-from-admin'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '${adminIp}/32'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
        }
      }
      {
        name: 'allow-cell-mtls-between-machines'
        properties: {
          priority: 120
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: subnetPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: machines[0].ip
          destinationPortRange: '8443'
        }
      }
      {
        name: 'allow-application-between-machines'
        properties: {
          priority: 130
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: subnetPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: machines[1].ip
          destinationPortRange: '9000'
        }
      }
      {
        name: 'allow-console-between-machines'
        properties: {
          priority: 140
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: subnetPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: machines[0].ip
          destinationPortRange: '9100'
        }
      }
      {
        // Azure lets every machine of a network talk to every other one on every port (a default rule of priority
        // 65000). This one, of a lower number, closes that: only the flows above exist.
        name: 'deny-everything-else'
        properties: {
          priority: 4000
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: 'tbp-devtest-net'
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [
        subnetPrefix
      ]
    }
    subnets: [
      {
        name: 'site'
        properties: {
          addressPrefix: subnetPrefix
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
    ]
  }
}

resource publicIp 'Microsoft.Network/publicIPAddresses@2023-11-01' = [for m in machines: {
  name: 'tbp-${m.name}-ip'
  location: location
  tags: tags
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}]

resource nic 'Microsoft.Network/networkInterfaces@2023-11-01' = [for (m, i) in machines: {
  name: 'tbp-${m.name}-nic'
  location: location
  tags: tags
  properties: {
    ipConfigurations: [
      {
        name: 'primary'
        properties: {
          privateIPAllocationMethod: 'Static'
          privateIPAddress: m.ip
          subnet: {
            id: vnet.properties.subnets[0].id
          }
          publicIPAddress: {
            id: publicIp[i].id
          }
        }
      }
    ]
  }
}]

resource vm 'Microsoft.Compute/virtualMachines@2024-03-01' = [for (m, i) in machines: {
  name: 'tbp-${m.name}'
  location: location
  tags: union(tags, { role: m.role })
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    osProfile: {
      computerName: 'tbp-${m.name}'
      adminUsername: adminUsername
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            {
              path: '/home/${adminUsername}/.ssh/authorized_keys'
              keyData: sshPublicKey
            }
          ]
        }
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'Debian'
        offer: 'debian-12'
        sku: '12-gen2'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        diskSizeGB: 30
        managedDisk: {
          storageAccountType: 'StandardSSD_LRS'
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic[i].id
        }
      ]
    }
  }
}]

@description('For each machine: its private address (the one the test uses) and its public address (the one you ssh to).')
output machines array = [for (m, i) in machines: {
  name: m.name
  role: m.role
  privateIp: m.ip
  publicIp: publicIp[i].properties.ipAddress
  ssh: 'ssh -i <your private key> ${adminUsername}@${publicIp[i].properties.ipAddress}'
}]
