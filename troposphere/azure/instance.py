# Copyright (c) 2012-2013, Mark Peek <mark@peek.org>
# All rights reserved.
#
# See LICENSE file for full license.

from . import AWSHelperFn, AWSObject, AzureObject, AWSProperty, Tags
from .validators import (
    boolean, exactly_one, integer, integer_range,
    network_port, positive_integer, vpn_pre_shared_key, vpn_tunnel_inside_cidr
)

try:
    from awacs.aws import Policy
    policytypes = (dict, Policy)
except ImportError:
    policytypes = dict,


class Tag(AWSProperty):
    props = {
        'Key': (basestring, True),
        'Value': (basestring, True)
    }

    def __init__(self, key=None, value=None, **kwargs):
        # provided for backward compatibility
        if key is not None:
            kwargs['Key'] = key
        if value is not None:
            kwargs['Value'] = value
        super(Tag, self).__init__(**kwargs)


class CustomerGateway(AWSObject):
    resource_type = "AWS::EC2::CustomerGateway"

    props = {
        'BgpAsn': (integer, True),
        'IpAddress': (basestring, True),
        'Tags': ((Tags, list), False),
        'Type': (basestring, True),
    }


class DHCPOptions(AWSObject):
    resource_type = "AWS::EC2::DHCPOptions"

    props = {
        'DomainName': (basestring, False),
        'DomainNameServers': (list, False),
        'NetbiosNameServers': (list, False),
        'NetbiosNodeType': (integer, False),
        'NtpServers': (list, False),
        'Tags': ((Tags, list), False),
    }


class EgressOnlyInternetGateway(AWSObject):
    resource_type = "AWS::EC2::EgressOnlyInternetGateway"

    props = {
        'VpcId': (basestring, True),
    }


class EIP(AWSObject):
    resource_type = "AWS::EC2::EIP"

    props = {
        'InstanceId': (basestring, False),
        'Domain': (basestring, False),
    }


class EIPAssociation(AWSObject):
    resource_type = "AWS::EC2::EIPAssociation"

    props = {
        'AllocationId': (basestring, False),
        'EIP': (basestring, False),
        'InstanceId': (basestring, False),
        'NetworkInterfaceId': (basestring, False),
        'PrivateIpAddress': (basestring, False),
    }


class FlowLog(AWSObject):
    resource_type = "AWS::EC2::FlowLog"

    props = {
        'DeliverLogsPermissionArn': (basestring, True),
        'LogGroupName': (basestring, True),
        'ResourceId': (basestring, True),
        'ResourceType': (basestring, True),
        'TrafficType': (basestring, True),
    }


class NatGateway(AWSObject):
    resource_type = "AWS::EC2::NatGateway"

    props = {
            'AllocationId': (basestring, True),
            'SubnetId': (basestring, True),
            'Tags': ((Tags, list), False),
    }


class EBSBlockDevice(AWSProperty):
    props = {
        'DeleteOnTermination': (boolean, False),
        'Encrypted': (boolean, False),
        'Iops': (integer, False),  # Conditional
        'SnapshotId': (basestring, False),  # Conditional
        'VolumeSize': (integer, False),  # Conditional
        'VolumeType': (basestring, False),
    }


NO_DEVICE = {}


class BlockDeviceMapping(AWSProperty):
    props = {
        'DeviceName': (basestring, True),
        'Ebs': (EBSBlockDevice, False),      # Conditional
        'NoDevice': (dict, False),
        'VirtualName': (basestring, False),  # Conditional
    }


class MountPoint(AWSProperty):
    props = {
        'Device': (basestring, True),
        'VolumeId': (basestring, True),
    }


class Placement(AWSProperty):
    props = {
        'AvailabilityZone': (basestring, False),
        'GroupName': (basestring, False),
    }


class Ipv6Addresses(AWSHelperFn):
    def __init__(self, address):
        self.data = {
            'Ipv6Address': address,
        }


class PrivateIpAddressSpecification(AWSProperty):
    props = {
        'Primary': (boolean, True),
        'PrivateIpAddress': (basestring, True),
    }


class NetworkInterfaceProperty(AWSProperty):
    props = {
        'AssociatePublicIpAddress': (boolean, False),
        'DeleteOnTermination': (boolean, False),
        'Description': (basestring, False),
        'DeviceIndex': (integer, True),
        'GroupSet': ([basestring], False),
        'NetworkInterfaceId': (basestring, False),
        'Ipv6AddressCount': (integer, False),
        'Ipv6Addresses': ([Ipv6Addresses], False),
        'PrivateIpAddress': (basestring, False),
        'PrivateIpAddresses': ([PrivateIpAddressSpecification], False),
        'SecondaryPrivateIpAddressCount': (integer, False),
        'SubnetId': (basestring, False),
    }


class AssociationParameters(AWSProperty):
    props = {
        'Key': (basestring, True),
        'Value': ([basestring], True),
    }


class SsmAssociations(AWSProperty):
    props = {
        'AssociationParameters': ([AssociationParameters], False),
        'DocumentName': (basestring, True),
    }


class Host(AWSObject):
    resource_type = "AWS::EC2::Host"

    props = {
        'AutoPlacement': (basestring, False),
        'AvailabilityZone': (basestring, True),
        'InstanceType': (basestring, True),
    }


class Instance(AWSObject):
    resource_type = "AWS::EC2::Instance"

    props = {
        'Affinity': (basestring, False),
        'AvailabilityZone': (basestring, False),
        'BlockDeviceMappings': (list, False),
        'DisableApiTermination': (boolean, False),
        'EbsOptimized': (boolean, False),
        'HostId': (basestring, False),
        'IamInstanceProfile': (basestring, False),
        'ImageId': (basestring, True),
        'InstanceInitiatedShutdownBehavior': (basestring, False),
        'InstanceType': (basestring, False),
        'Ipv6AddressCount': (integer, False),
        'Ipv6Addresses': ([Ipv6Addresses], False),
        'KernelId': (basestring, False),
        'KeyName': (basestring, False),
        'Monitoring': (boolean, False),
        'NetworkInterfaces': ([NetworkInterfaceProperty], False),
        'PlacementGroupName': (basestring, False),
        'PrivateIpAddress': (basestring, False),
        'RamdiskId': (basestring, False),
        'SecurityGroupIds': (list, False),
        'SecurityGroups': (list, False),
        'SsmAssociations': ([SsmAssociations], False),
        'SourceDestCheck': (boolean, False),
        'SubnetId': (basestring, False),
        'Tags': ((Tags, list), False),
        'Tenancy': (basestring, False),
        'UserData': (basestring, False),
        'Volumes': (list, False),
    }


class InternetGateway(AWSObject):
    resource_type = "AWS::EC2::InternetGateway"

    props = {
        'Tags': ((Tags, list), False),
    }


class NetworkAcl(AWSObject):
    resource_type = "AWS::EC2::NetworkAcl"

    props = {
        'Tags': ((Tags, list), False),
        'VpcId': (basestring, True),
    }


class ICMP(AWSProperty):
    props = {
        'Code': (integer, False),
        'Type': (integer, False),
    }


class PortRange(AWSProperty):
    props = {
        'From': (network_port, False),
        'To': (network_port, False),
    }


class NetworkAclEntry(AWSObject):
    resource_type = "AWS::EC2::NetworkAclEntry"

    props = {
        'CidrBlock': (basestring, False),
        'Egress': (boolean, False),
        'Icmp': (ICMP, False),  # Conditional
        'Ipv6CidrBlock': (basestring, False),
        'NetworkAclId': (basestring, True),
        'PortRange': (PortRange, False),  # Conditional
        'Protocol': (network_port, True),
        'RuleAction': (basestring, True),
        'RuleNumber': (integer_range(1, 32766), True),
    }

    def validate(self):
        conds = [
            'CidrBlock',
            'Ipv6CidrBlock',
        ]
        exactly_one(self.__class__.__name__, self.properties, conds)


class NetworkInterfaceAttachment(AWSObject):
    resource_type = "AWS::EC2::NetworkInterfaceAttachment"

    props = {
        'DeleteOnTermination': (boolean, False),
        'DeviceIndex': (integer, True),
        'InstanceId': (basestring, True),
        'NetworkInterfaceId': (basestring, True),
    }


PERMISSION_INSTANCE_ATTACH = 'INSTANCE-ATTACH'
PERMISSION_EIP_ASSOCIATE = 'EIP-ASSOCIATE'


class NetworkInterfacePermission(AWSObject):
    resource_type = "AWS::EC2::NetworkInterfacePermission"

    props = {
        'AwsAccountId': (basestring, True),
        'NetworkInterfaceId': (basestring, True),
        'Permission': (basestring, True),
    }


class Route(AWSObject):
    resource_type = "AWS::EC2::Route"

    props = {
        'DestinationCidrBlock': (basestring, False),
        'DestinationIpv6CidrBlock': (basestring, False),
        'EgressOnlyInternetGatewayId': (basestring, False),
        'GatewayId': (basestring, False),
        'InstanceId': (basestring, False),
        'NatGatewayId': (basestring, False),
        'NetworkInterfaceId': (basestring, False),
        'RouteTableId': (basestring, True),
        'VpcPeeringConnectionId': (basestring, False),
    }

    def validate(self):
        cidr_conds = [
            'DestinationCidrBlock',
            'DestinationIpv6CidrBlock',
        ]
        gateway_conds = [
            'EgressOnlyInternetGatewayId',
            'GatewayId',
            'InstanceId',
            'NatGatewayId',
            'NetworkInterfaceId',
            'VpcPeeringConnectionId'
        ]
        exactly_one(self.__class__.__name__, self.properties, cidr_conds)
        exactly_one(self.__class__.__name__, self.properties, gateway_conds)


class SecurityGroupEgress(AWSObject):
    resource_type = "AWS::EC2::SecurityGroupEgress"

    props = {
        'CidrIp': (basestring, False),
        'CidrIpv6': (basestring, False),
        'Description': (basestring, False),
        'DestinationPrefixListId': (basestring, False),
        'DestinationSecurityGroupId': (basestring, False),
        'FromPort': (network_port, True),
        'GroupId': (basestring, True),
        'IpProtocol': (basestring, True),
        'ToPort': (network_port, True),
        #
        # Workaround for a bug in CloudFormation and EC2 where the
        # DestinationSecurityGroupId property is ignored causing
        # egress rules targeting a security group to be ignored.
        # Using SourceSecurityGroupId instead works fine even in
        # egress rules. AWS have known about this bug for a while.
        #
        'SourceSecurityGroupId': (basestring, False),
    }

    def validate(self):
        conds = [
            'CidrIp',
            'CidrIpv6',
            'DestinationPrefixListId',
            'DestinationSecurityGroupId',
        ]
        exactly_one(self.__class__.__name__, self.properties, conds)


class SecurityGroupIngress(AWSObject):
    resource_type = "AWS::EC2::SecurityGroupIngress"

    props = {
        'CidrIp': (basestring, False),
        'CidrIpv6': (basestring, False),
        'Description': (basestring, False),
        'FromPort': (network_port, False),  # conditional
        'GroupName': (basestring, False),
        'GroupId': (basestring, False),
        'IpProtocol': (basestring, True),
        'SourceSecurityGroupName': (basestring, False),
        'SourceSecurityGroupId': (basestring, False),
        'SourceSecurityGroupOwnerId': (basestring, False),
        'ToPort': (network_port, False),  # conditional
    }

    def validate(self):
        conds = [
            'CidrIp',
            'CidrIpv6',
            'SourceSecurityGroupName',
            'SourceSecurityGroupId',
        ]
        exactly_one(self.__class__.__name__, self.properties, conds)


class SecurityGroupRule(AWSProperty):
    props = {
        'CidrIp': (basestring, False),
        'CidrIpv6': (basestring, False),
        'Description': (basestring, False),
        'FromPort': (network_port, False),
        'IpProtocol': (basestring, True),
        'SourceSecurityGroupId': (basestring, False),
        'SourceSecurityGroupName': (basestring, False),
        'SourceSecurityGroupOwnerId': (basestring, False),
        'ToPort': (network_port, False),
        'DestinationSecurityGroupId': (basestring, False),
    }


class Subnet(AWSObject):
    resource_type = "AWS::EC2::Subnet"

    props = {
        'AssignIpv6AddressOnCreation': (boolean, False),
        'AvailabilityZone': (dict, False),
        'CidrBlock': (basestring, True),
        'Ipv6CidrBlock': (basestring, False),
        'MapPublicIpOnLaunch': (boolean, False),
        'Tags': ((Tags, list), False),
        'VpcId': (basestring, True),
    }

    def validate(self):
        if 'Ipv6CidrBlock' in self.properties:
            if not self.properties.get('AssignIpv6AddressOnCreation'):
                raise ValueError(
                    "If Ipv6CidrBlock is present, "
                    "AssignIpv6AddressOnCreation must be set to True"
                )


class SubnetNetworkAclAssociation(AWSObject):
    resource_type = "AWS::EC2::SubnetNetworkAclAssociation"

    props = {
        'SubnetId': (basestring, True),
        'NetworkAclId': (basestring, True),
    }


class SubnetRouteTableAssociation(AWSObject):
    resource_type = "AWS::EC2::SubnetRouteTableAssociation"

    props = {
        'RouteTableId': (basestring, True),
        'SubnetId': (basestring, True),
    }


class Volume(AWSObject):
    resource_type = "AWS::EC2::Volume"

    props = {
        'AutoEnableIO': (boolean, False),
        'AvailabilityZone': (basestring, True),
        'Encrypted': (boolean, False),
        'Iops': (positive_integer, False),
        'KmsKeyId': (basestring, False),
        'Size': (positive_integer, False),
        'SnapshotId': (basestring, False),
        'Tags': ((Tags, list), False),
        'VolumeType': (basestring, False),
    }


class VolumeAttachment(AWSObject):
    resource_type = "AWS::EC2::VolumeAttachment"

    props = {
        'Device': (basestring, True),
        'InstanceId': (basestring, True),
        'VolumeId': (basestring, True),
    }


class VPC(AWSObject):
    resource_type = "AWS::EC2::VPC"

    props = {
        'CidrBlock': (basestring, True),
        'EnableDnsSupport': (boolean, False),
        'EnableDnsHostnames': (boolean, False),
        'InstanceTenancy': (basestring, False),
        'Tags': ((Tags, list), False),
    }


class VPCDHCPOptionsAssociation(AWSObject):
    resource_type = "AWS::EC2::VPCDHCPOptionsAssociation"

    props = {
        'DhcpOptionsId': (basestring, True),
        'VpcId': (basestring, True),
    }


class VPCEndpoint(AWSObject):
        resource_type = "AWS::EC2::VPCEndpoint"

        props = {
            'PolicyDocument': (policytypes, False),
            'RouteTableIds': ([basestring], False),
            'ServiceName': (basestring, True),
            'VpcId': (basestring, True),
        }


class VPCGatewayAttachment(AWSObject):
    resource_type = "AWS::EC2::VPCGatewayAttachment"

    props = {
        'InternetGatewayId': (basestring, False),
        'VpcId': (basestring, True),
        'VpnGatewayId': (basestring, False),
    }


class VpnTunnelOptionsSpecification(AWSProperty):
    props = {
        'PreSharedKey': (vpn_pre_shared_key, False),
        'TunnelInsideCidr': (vpn_tunnel_inside_cidr, False),
    }


class VPNConnection(AWSObject):
    resource_type = "AWS::EC2::VPNConnection"

    props = {
        'Type': (basestring, True),
        'CustomerGatewayId': (basestring, True),
        'StaticRoutesOnly': (boolean, False),
        'Tags': ((Tags, list), False),
        'VpnGatewayId': (basestring, True),
        'VpnTunnelOptionsSpecifications': (
            [VpnTunnelOptionsSpecification], False
        ),
    }


class VPNConnectionRoute(AWSObject):
    resource_type = "AWS::EC2::VPNConnectionRoute"

    props = {
        'DestinationCidrBlock': (basestring, True),
        'VpnConnectionId': (basestring, True),
    }


class VPNGateway(AWSObject):
    resource_type = "AWS::EC2::VPNGateway"

    props = {
        'AmazonSideAsn': (positive_integer, False),
        'Type': (basestring, True),
        'Tags': ((Tags, list), False),
    }


class VPNGatewayRoutePropagation(AWSObject):
    resource_type = "AWS::EC2::VPNGatewayRoutePropagation"

    props = {
        'RouteTableIds': ([basestring], True),
        'VpnGatewayId': (basestring, True),
    }


class VPCPeeringConnection(AWSObject):
    resource_type = "AWS::EC2::VPCPeeringConnection"

    props = {
        'PeerVpcId': (basestring, True),
        'VpcId': (basestring, True),
        'Tags': ((Tags, list), False),
        'PeerOwnerId': (basestring, False),
        'PeerRoleArn': (basestring, False),
    }


class Monitoring(AWSProperty):
    props = {
        'Enabled': (boolean, False),
    }


class NetworkInterfaces(AWSProperty):
    props = {
        'AssociatePublicIpAddress': (boolean, False),
        'DeleteOnTermination': (boolean, False),
        'Description': (basestring, False),
        'DeviceIndex': (integer, True),
        'Groups': ([basestring], False),
        'Ipv6AddressCount': (integer, False),
        'Ipv6Addresses': ([Ipv6Addresses], False),
        'NetworkInterfaceId': (basestring, False),
        'PrivateIpAddresses': ([PrivateIpAddressSpecification], False),
        'SecondaryPrivateIpAddressCount': (integer, False),
        'SubnetId': (basestring, False),
    }


class SecurityGroups(AWSProperty):
    props = {
        'GroupId': (basestring, False),
    }


class IamInstanceProfile(AWSProperty):
    props = {
        'Arn': (basestring, False),
    }


class LaunchSpecifications(AWSProperty):
    props = {
        'BlockDeviceMappings': ([BlockDeviceMapping], False),
        'EbsOptimized': (boolean, False),
        'IamInstanceProfile': (IamInstanceProfile, False),
        'ImageId': (basestring, True),
        'InstanceType': (basestring, True),
        'KernelId': (basestring, False),
        'KeyName': (basestring, False),
        'Monitoring': (Monitoring, False),
        'NetworkInterfaces': ([NetworkInterfaces], False),
        'Placement': (Placement, False),
        'RamdiskId': (basestring, False),
        'SecurityGroups': ([SecurityGroups], False),
        'SpotPrice': (basestring, False),
        'SubnetId': (basestring, False),
        'UserData': (basestring, False),
        'WeightedCapacity': (positive_integer, False),
    }


class SpotFleetRequestConfigData(AWSProperty):
    props = {
        'AllocationStrategy': (basestring, False),
        'ExcessCapacityTerminationPolicy': (basestring, False),
        'IamFleetRole': (basestring, True),
        'ReplaceUnhealthyInstances': (boolean, False),
        'LaunchSpecifications': ([LaunchSpecifications], True),
        'SpotPrice': (basestring, False),
        'TargetCapacity': (positive_integer, True),
        'TerminateInstancesWithExpiration': (boolean, False),
        'Type': (basestring, False),
        'ValidFrom': (basestring, False),
        'ValidUntil': (basestring, False),
    }


class SpotFleet(AWSObject):
    resource_type = "AWS::EC2::SpotFleet"

    props = {
        'SpotFleetRequestConfigData': (SpotFleetRequestConfigData, True),
    }


class PlacementGroup(AWSObject):
    resource_type = "AWS::EC2::PlacementGroup"

    props = {
        'Strategy': (basestring, True),
    }


class SubnetCidrBlock(AWSObject):
    resource_type = "AWS::EC2::SubnetCidrBlock"

    props = {
        'Ipv6CidrBlock': (basestring, True),
        'SubnetId': (basestring, True),
    }


class VPCCidrBlock(AWSObject):
    resource_type = "AWS::EC2::VPCCidrBlock"

    props = {
        'AmazonProvidedIpv6CidrBlock': (boolean, False),
        'CidrBlock': (basestring, False),
        'VpcId': (basestring, True),
    }


class StorageAccount(AWSObject):
    resource_type = "Microsoft.Storage/storageAccounts"

    props = {
        'accountType': (basestring, False),
    }


class PublicIpAddress(AWSObject):
    resource_type = "Microsoft.Network/publicIPAddresses"

    props = {
        'publicIPAllocationMethod': (basestring, False),
        'dnsSettings': (dict, False),
    }


class AzureSecurityRules(AWSObject):
    props = {
        'description': (basestring, False),
        'protocol': (basestring, False),
        'sourcePortRange': (basestring, False),
        'destinationPortRange': (basestring, False),
        'sourceAddressPrefix': (basestring, False),
        'destinationAddressPrefix': (basestring, False),
        'access': (basestring, False),
        'direction': (basestring, False),
        'priority': (integer, False),
    }


class SecurityGroup(AWSObject):
    resource_type = "Microsoft.Network/networkSecurityGroups"

    props = {
        'securityRules': ([AzureSecurityRules], False),
    }


class RouteTableRoute(AWSObject):
    props = {
        'addressPrefix': (basestring, False),
        'nextHopType': (basestring, False),
        'nextHopIpAddress': (basestring, False),
    }


class RouteTable(AWSObject):
    resource_type = "Microsoft.Network/routeTables"

    props = {
        'routes': ([RouteTableRoute], False),
    }


class VirtualNetSubnet(AWSObject):
    props = {
        'addressPrefix': (basestring, False),
        'networkSecurityGroup': (dict, False),
    }


class VirtualNetwork(AWSObject):
    resource_type = "Microsoft.Network/virtualNetworks"

    props = {
        'mode': (basestring, False),
        'addressSpace': (dict, False),
        'subnets': ([VirtualNetSubnet], False),
    }


class AzureProp(AWSProperty):
    props = {
        'privateIPAllocationMethod': (basestring, False),
        'privateIPAddress': (basestring, False),
        'subnet': (dict, False),
        'publicIPAddress': (dict, False),
    }


class NetworkIntIpConfig(AzureObject):
    props = {
        'name': (basestring, False),
        'privateIPAllocationMethod': (basestring, False),
        'privateIPAddress': (basestring, False),
        'subnet': (dict, False),
        'publicIPAddress': (dict, False),
    }


class NetworkInterface(AWSObject):
    resource_type = "Microsoft.Network/networkInterfaces"

    props = {
        'tags': (dict, False),
        'enableIPForwarding': (basestring, False),
        'ipConfigurations': ([NetworkIntIpConfig], False),
    }


class VirtualMachine(AWSObject):
    resource_type = "Microsoft.Compute/virtualMachines"

    props = {
        'hardwareProfile': (dict, False),
        'osProfile': (dict, False),
        'storageProfile': (dict, False),
        'networkProfile': (dict, False),
    }


class hardwareProfile(AWSProperty):
    props = {
        'vmSize': (basestring, False),
    }


class osProfile(AWSProperty):
    props = {
        'computername': (basestring, False),
        'adminUsername': (basestring, False),
        'adminPassword': (basestring, False),
    }


class storageProfile(AWSProperty):
    props = {
        'imageReference': (dict, False),
        'osDisk': (dict, False),
    }


class networkProfile(AWSProperty):
    props = {
        'networkInterfaces': (list, False),
    }


class imageReference(AWSProperty):
    props = {
        'publisher': (basestring, False),
        'offer': (basestring, False),
        'sku': (basestring, False),
        'version': (basestring, False),
    }


class osDisk(AWSProperty):
    props = {
        'name': (basestring, False),
        'vhd': (dict, False),
        'caching': (basestring, False),
        'createOption': (basestring, False),
    }


class networkInterfaces(AWSProperty):
    props = {
        'id': (basestring, False),
        'properties': (basestring, False),
    }


class vhd(AWSProperty):
    props = {
        'uri': (basestring, False),
    }


class VirtualMachineExtension(AWSObject):
    resource_type = "Microsoft.Compute/virtualMachines/extensions"

    props = {
        'publisher': (basestring, False),
        'type': (basestring, False),
        'typeHandlerVersion': (basestring, False),
        'settings': (dict, False),
    }


class settings(AWSProperty):
    props = {
        'fileUris': (list, False),
        'commandToExecute': (basestring, False),
    }


class ResourceDeploymentRouteTable(AWSObject):
    props = {
        'id': (basestring, False),
    }


class ResourceDeploymentResource(AWSProperty):
    resource_type = "Microsoft.Network/virtualNetworks/subnets"
    props = {
        'mode': (basestring, False),
        'addressPrefix': (basestring, False),
        'routeTable': (dict, False),
    }


class ResourceDeploymentTemplate(AWSProperty):
    props = {
        '$' + 'schema': (basestring, False),
        'contentVersion': (basestring, False),
        'resources': ([ResourceDeploymentResource], False),
    }


class ResourceDeployment(AWSObject):
    resource_type = "Microsoft.Resources/deployments"

    props = {
        'mode': (basestring, False),
        'template': (dict, False),
    }


class properties(AWSProperty):
    props = {
        'privateIPAllocationMethod': (basestring, False),
        'privateIPAddress': (basestring, False),
        'publicIPAddress': (dict, False),
    }


class publicIPAddress(AWSProperty):
    props = {
        'id': (basestring, False),
    }
