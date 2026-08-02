@description('Azure region for the Windows validation VM.')
param location string = resourceGroup().location

@description('Name of the Windows validation VM.')
param vmName string = 'metatron-winval-azure-01'

@description('Size of the Windows validation VM.')
param vmSize string = 'Standard_D4s_v5'

@description('Administrator username for the Windows VM.')
param adminUsername string = 'metatronadmin'

@secure()
@description('Administrator password for the Windows VM.')
param adminPassword string

@description('Public IP SKU for the VM.')
@allowed([
  'Standard'
])
param publicIpSku string = 'Standard'

@description('CIDR allowed to reach RDP and WinRM. Narrow this before deployment.')
param allowedSourceAddressPrefix string = '*'

@description('Marketplace image publisher.')
param imagePublisher string = 'MicrosoftWindowsServer'

@description('Marketplace image offer.')
param imageOffer string = 'WindowsServer'

@description('Marketplace image SKU. Use a Trusted Launch capable Gen2 image.')
param imageSku string = '2022-datacenter-azure-edition'

@description('Marketplace image version.')
param imageVersion string = 'latest'

@description('OS disk size in GiB.')
@minValue(64)
param osDiskSizeGB int = 128

@description('Address prefix for the validation VNet.')
param vnetAddressPrefix string = '10.42.0.0/16'

@description('Address prefix for the validation subnet.')
param subnetAddressPrefix string = '10.42.0.0/24'

var publicIpName = '${vmName}-pip'
var nsgName = '${vmName}-nsg'
var vnetName = '${vmName}-vnet'
var nicName = '${vmName}-nic'

resource publicIp 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: publicIpName
  location: location
  sku: {
    name: publicIpSku
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource nsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: nsgName
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-rdp'
        properties: {
          priority: 100
          access: 'Allow'
          direction: 'Inbound'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '3389'
          sourceAddressPrefix: allowedSourceAddressPrefix
          destinationAddressPrefix: '*'
        }
      }
      {
        name: 'allow-winrm-http'
        properties: {
          priority: 110
          access: 'Allow'
          direction: 'Inbound'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '5985'
          sourceAddressPrefix: allowedSourceAddressPrefix
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: vnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        vnetAddressPrefix
      ]
    }
    subnets: [
      {
        name: 'default'
        properties: {
          addressPrefix: subnetAddressPrefix
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
    ]
  }
}

resource nic 'Microsoft.Network/networkInterfaces@2024-05-01' = {
  name: nicName
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: {
            id: vnet.properties.subnets[0].id
          }
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: {
            id: publicIp.id
          }
        }
      }
    ]
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: vmName
  location: location
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    securityProfile: {
      securityType: 'TrustedLaunch'
      uefiSettings: {
        secureBootEnabled: true
        vTpmEnabled: true
      }
    }
    storageProfile: {
      imageReference: {
        publisher: imagePublisher
        offer: imageOffer
        sku: imageSku
        version: imageVersion
      }
      osDisk: {
        createOption: 'FromImage'
        diskSizeGB: osDiskSizeGB
        managedDisk: {
          storageAccountType: 'Premium_LRS'
        }
      }
    }
    osProfile: {
      computerName: vmName
      adminUsername: adminUsername
      adminPassword: adminPassword
      windowsConfiguration: {
        enableAutomaticUpdates: true
        provisionVMAgent: true
        patchSettings: {
          patchMode: 'AutomaticByOS'
          assessmentMode: 'ImageDefault'
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
        }
      ]
    }
  }
}

output vmId string = vm.id
output publicIpAddress string = publicIp.properties.ipAddress
output trustedLaunchEnabled bool = vm.properties.securityProfile.uefiSettings.secureBootEnabled && vm.properties.securityProfile.uefiSettings.vTpmEnabled
