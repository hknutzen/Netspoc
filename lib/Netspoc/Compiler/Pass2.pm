package Netspoc::Compiler::Pass2;

=head1 NAME

Pass 2 of Netspoc - A Network Security Policy Compiler

=head1 COPYRIGHT AND DISCLAIMER

(C) 2018 by Heinz Knutzen <heinz.knutzen@googlemail.com>

http://hknutzen.github.com/Netspoc

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

=cut

use strict;
use warnings;
use JSON;
use File::Basename;
use Netspoc::Compiler::GetArgs qw(get_args);
use Netspoc::Compiler::File qw(read_file read_file_lines);
use Netspoc::Compiler::Common;
use open qw(:std :utf8);
use NetAddr::IP::Util;

sub create_ip_obj {
    my ($ip_net) = @_;
    my ($ip, $prefix) = split '/', $ip_net;
    return { ip => ip2bitstr($ip), mask => prefix2mask($prefix),
             name => $ip_net };
}

sub get_ip_obj {
    my ($ip, $mask, $ip_net2obj) = @_;
    my $name = bitstr2ip($ip) . '/' . mask2prefix($mask);
    return $ip_net2obj->{$name} ||= { ip => $ip, mask => $mask, name => $name };
}

sub create_prt_obj {
    my ($descr) = @_;
    my ($proto, $i1, $i2, $established) = split ' ', $descr;
    my $prt = { proto => $proto, name => $descr };

    if ($proto eq 'tcp' or $proto eq 'udp') {
        $prt->{range} = [ $i1, $i2 ];
        $prt->{established} = 1 if $established;
    }
    elsif ($proto eq 'icmp') {
        if (defined($i1)) {
            $prt->{type} = $i1;
            if (defined($i2)) {
                $prt->{code} = $i2
            }
        }
    }
    return $prt;
}

sub get_net00_addr {
    return $config->{ipv6} ? '::/0' : '0.0.0.0/0';
}

sub setup_ip_net_relation {
    my ($ip_net2obj) = @_;
    my $net00 = get_net00_addr();
    $ip_net2obj->{$net00} ||=  create_ip_obj($net00);
    my %mask_ip_hash;

    # Collect networks into %mask_ip_hash.
    for my $network (values %$ip_net2obj) {
        my ($ip, $mask) = @{$network}{qw(ip mask)};
        $mask_ip_hash{$mask}->{$ip} = $network;
    }

    # Compare networks.
    # Go from smaller to larger networks.
    my @mask_list = reverse sort keys %mask_ip_hash;
    while (my $mask = shift @mask_list) {

        # No supernets available
        last if not @mask_list;

        my $ip_hash = $mask_ip_hash{$mask};
        for my $ip (sort keys %$ip_hash) {

            my $subnet = $ip_hash->{$ip};

            # Find networks which include current subnet.
            # @mask_list holds masks of potential supernets.
            for my $m (@mask_list) {

                my $i = $ip & $m;
                my $bignet = $mask_ip_hash{$m}->{$i} or next;
                $subnet->{up} = $bignet;

#                debug "$subnet->{name} < $bignet->{name}";
                last;
            }
        }
    }

    # Propagate content of attributes {opt_networks} to all subnets.
    # Go from large to smaller networks.
    for my $obj (sort { $a->{mask} cmp $b->{mask} } values %$ip_net2obj) {
        my $up = $obj->{up} or next;
        if (my $opt_networks = $up->{opt_networks}) {
            $obj->{opt_networks} = $opt_networks;
#           debug "secondary: $obj->{name} $opt_networks->{name}";
        }
    }
}

sub mark_supernets_of_need_protect {
    my ($need_protect) = @_;
    for my $interface (@$need_protect) {
        my $up = $interface->{up};
        while ($up) {
            $up->{is_supernet_of_need_protect}->{$interface} = 1;
            $up = $up->{up};
        }
    }
}

# Needed for model=Linux.
sub add_tcp_udp_icmp {
    my ($prt2obj) = @_;
    $prt2obj->{'tcp 1 65535'} ||= create_prt_obj('tcp 1 65535');
    $prt2obj->{'udp 1 65535'} ||= create_prt_obj('udp 1 65535');
    $prt2obj->{icmp} ||= create_prt_obj('icmp');
}

# Set {up} relation from port range to the smallest port range which
# includes it.
# If no including range is found, link it with next larger protocol.
# Set attribute {has_neighbor} to range adjacent to upper port.
# Abort on overlapping ranges.
sub order_ranges {
    my ($proto, $prt2obj, $up) = @_;
    my @sorted =

      # Sort by low port. If low ports are equal, sort reverse by high port.
      # I.e. larger ranges coming first, if there are multiple ranges
      # with identical low port.
      sort {
             $a->{range}->[0] <=> $b->{range}->[0]
          || $b->{range}->[1] <=> $a->{range}->[1]
      }
      grep { $_->{proto} eq $proto and not $_->{established} }
      values %$prt2obj;

    # Check current range [a1, a2] for sub-ranges, starting at position $i.
    # Set attributes {up} and {has_neighbor}.
    # Return position of range which isn't sub-range or undef
    # if end of array is reached.
    my $check_subrange;

    $check_subrange = sub {
        my ($a, $a1, $a2, $i) = @_;
        while (1) {
            return if $i == @sorted;
            my $b = $sorted[$i];
            my ($b1, $b2) = @{ $b->{range} };

            # Neighbors
            # aaaabbbb
            if ($a2 + 1 == $b1) {

                # Mark protocol as candidate for joining of port ranges during
                # optimization.
                $a->{has_neighbor} = $b->{has_neighbor} = 1;

                # Mark other ranges having identical start port.
                my $j = $i + 1;
                while ($j < @sorted) {
                    my $c = $sorted[$j];
                    my $c1 = $c->{range}->[0];
                    $a2 + 1 == $c1 or last;
                    $c->{has_neighbor} = 1;
                    $j++;
                }
            }

            # Not related.
            # aaaa    bbbbb
            return $i if $a2 < $b1;

            # $a includes $b.
            # aaaaaaa
            #  bbbbb
            if ($a2 >= $b2) {
                $b->{up} = $a;
                $i = $check_subrange->($b, $b1, $b2, $i + 1);

                # Stop at end of array.
                $i or return;
                next;
            }

            # $a and $b are overlapping.
            # aaaaa
            #   bbbbbb
            # uncoverable statement
            fatal_err("Unexpected overlapping ranges [$a1-$a2] [$b1-$b2]");
        }
    };

    @sorted or return;
    my $index = 0;
    while (1) {
        my $a = $sorted[$index];
        $a->{up} = $up;
        my ($a1, $a2) = @{ $a->{range} };
        $index++;
        $index = $check_subrange->($a, $a1, $a2, $index) or last;
    }
    return;
}

sub setup_prt_relation {
    my ($prt2obj) = @_;
    my $prt_ip = $prt2obj->{ip} ||= create_prt_obj('ip');
    my $icmp_up = $prt2obj->{icmp} || $prt_ip;
    for my $prt (values %$prt2obj) {
        my $proto = $prt->{proto};
        if ($proto eq 'icmp') {
            my $type = $prt->{type};
            if (defined $type) {
                if (defined $prt->{code}) {
                    $prt->{up} = $prt2obj->{"icmp $type"} || $icmp_up;
                }
                else {
                    $prt->{up} = $icmp_up;
                }
            }
            else {
                $prt->{up} = $prt_ip;
            }
        }

        # Numeric protocol.
        elsif ($proto =~ /^\d+$/) {
            $prt->{up} = $prt_ip;
        }
    }

    order_ranges('tcp', $prt2obj, $prt_ip);
    order_ranges('udp', $prt2obj, $prt_ip);

    if (my $tcp_establ = $prt2obj->{'tcp 1 65535 established'}) {
        $tcp_establ->{up} = $prt2obj->{'tcp 1 65535'} || $prt_ip;
    }

    return;
}

#sub print_rule {
#    my ($rule) = @_;
#    my ($deny, $src, $dst, $prt) = @{$rule}{qw(deny src dst prt)};
#    my $action = $deny ? 'deny' : 'permit';
#    return "$action $src->{name} $dst->{name} $prt->{name}";
#}

sub optimize_redundant_rules {
    my ($cmp_hash, $chg_hash, $acl_info) = @_;
    my $ip_net2obj = $acl_info->{ip_net2obj};
    my $prt2obj    = $acl_info->{prt2obj};
    my $changed;
    for my $deny (keys %$chg_hash) {
     my $chg_hash = $chg_hash->{$deny};
     while (1) {
      if (my $cmp_hash = $cmp_hash->{$deny}) {
       for my $src_range_name (keys %$chg_hash) {
       my $chg_hash = $chg_hash->{$src_range_name};
        my $src_range = $prt2obj->{$src_range_name};
        while (1) {
         if (my $cmp_hash = $cmp_hash->{$src_range->{name}}) {
          for my $src_name (keys %$chg_hash) {
           my $chg_hash = $chg_hash->{$src_name};
           my $src = $ip_net2obj->{$src_name};
           while (1) {
            if (my $cmp_hash = $cmp_hash->{$src->{name}}) {
             for my $dst_name (keys %$chg_hash) {
              my $chg_hash = $chg_hash->{$dst_name};
              my $dst = $ip_net2obj->{$dst_name};
              while (1) {
               if (my $cmp_hash = $cmp_hash->{$dst->{name}}) {
                for my $chg_rule (values %$chg_hash) {
                 next if $chg_rule->{deleted};
                 my $prt = $chg_rule->{prt};
                 my $chg_log = $chg_rule->{log} || '';
                 while (1) {
                  if (my $cmp_rule = $cmp_hash->{$prt->{name}}) {
                   my $cmp_log = $cmp_rule->{log} || '';
                   if ($cmp_rule ne $chg_rule && $cmp_log eq $chg_log) {

#                   debug "del: ", print_rule $chg_rule;
                    $chg_rule->{deleted} = $cmp_rule;
                    $changed = 1;
                    last;
                   }
                  }
                  $prt = $prt ->{up} or last;
                 }
                }
               }
               $dst = $dst->{up} or last;
              }
             }
            }
            $src = $src->{up} or last;
           }
          }
         }
         $src_range = $src_range->{up} or last;
        }
       }
      }
      last if $deny;
      $deny = 1;
     }
    }
    return $changed;
}

sub optimize_rules {
    my ($rules, $acl_info) = @_;
    my $prt_ip = $acl_info->{prt2obj}->{ip};

    # For comparing redundant rules.
    my %rule_tree;

    # Fill rule tree.
    my $changed = 0;
    for my $rule (@$rules) {

        my ($src, $dst, $deny, $src_range, $prt) =
            @{$rule}{qw(src dst deny src_range prt)};
        $deny      ||= '';
        $src_range ||= $prt_ip;
        $src = $src->{name};
        $dst = $dst->{name};
        $src_range = $src_range->{name};
        $prt = $prt->{name};

        # Remove duplicate rules.
        if ($rule_tree{$deny}->{$src_range}->{$src}->{$dst}->{$prt}) {
            $rule->{deleted} = 1;
            $changed = 1;
            next;
        }
        $rule_tree{$deny}->{$src_range}->{$src}->{$dst}->{$prt} = $rule;
    }

    my $changed2 =
        optimize_redundant_rules (\%rule_tree, \%rule_tree, $acl_info);
    $changed ||= $changed2;

    # Implement rules as secondary rule, if possible.
    my %secondary_tree;
    my $ip_key = $prt_ip->{name};
    for my $rule (@$rules) {
        $rule->{opt_secondary} or next;
        next if $rule->{deleted};

        my ($src, $dst) = @{$rule}{qw(src dst)};
        next if $src->{no_opt_addrs};
        next if $dst->{no_opt_addrs};

        # Replace obj by supernet.
        if (my $supernet = $src->{opt_networks}) {
            $src = $rule->{src} = $supernet;
        }
        if (my $supernet = $dst->{opt_networks} and not $dst->{need_protect}) {
            $dst = $rule->{dst} = $supernet;
        }

        # Change protocol to IP.
        $rule->{prt} = $prt_ip;

        # Add new rule to secondary_tree. If multiple rules are
        # converted to the same secondary rule, only the first one
        # will be created.
        $src = $src->{name};
        $dst = $dst->{name};
        if ($secondary_tree{''}->{$ip_key}->{$src}->{$dst}->{$ip_key}) {

#           debug("sec delete: ", print_rule $rule);
            $rule->{deleted} = 1;
            $changed = 1;
        }
        else {

#           debug("sec: ", print_rule $rule);
            $secondary_tree{''}->{$ip_key}->{$src}->{$dst}->{$ip_key} = $rule;
        }
    }

    if (keys %secondary_tree) {
        $changed2 = optimize_redundant_rules(\%secondary_tree,
                                             \%secondary_tree, $acl_info);
        $changed ||= $changed2;
        $changed2 = optimize_redundant_rules(\%secondary_tree,
                                             \%rule_tree, $acl_info);
        $changed ||= $changed2;
    }

    if ($changed) {
        $rules = [ grep { not $_->{deleted} } @$rules ];
    }
    return $rules;
}

# Join adjacent port ranges.
sub join_ranges {
    my ($rules, $prt2obj) = @_;
    my $changed;
    my %key2rules;
    for my $rule (@$rules) {
        my ($deny, $src, $dst, $src_range, $prt) =
            @{$rule}{qw(deny src dst src_range prt)};

        # Only ranges which have a neighbor may be successfully optimized.
        # Currently only dst_ranges are handled.
        $prt->{has_neighbor} or next;

        # Collect rules with identical deny/src/dst/src_range log values
        # and identical TCP or UDP protocol.
        $deny      ||= '';
        $src_range ||= '';
        my $key = "$deny,$src,$dst,$src_range,$prt->{proto}";
        if (my $log = $rule->{log}) {
            $key .= ",$log";
        }
        push @{ $key2rules{$key} }, $rule;
    }

    for my $rules (values %key2rules) {
        @$rules >= 2 or next;

        # When sorting these rules by low port number,
        # rules with adjacent protocols will placed
        # side by side. There can't be overlaps,
        # because they have been split in function
        # 'order_ranges'. There can't be sub-ranges,
        # because they have been deleted as redundant
        # already.
        my @sorted = sort {
            $a->{prt}->{range}->[0] <=> $b->{prt}->{range}->[0]
        } @$rules;
        my $i      = 0;
        my $rule_a = $sorted[$i];
        my ($a1, $a2) = @{ $rule_a->{prt}->{range} };
        while (++$i < @sorted) {
            my $rule_b = $sorted[$i];
            my ($b1, $b2) = @{ $rule_b->{prt}->{range} };
            if ($a2 + 1 == $b1) {

                # Found adjacent port ranges.
                if (my $range = delete $rule_a->{range}) {

                    # Extend range of previous two or more elements.
                    $range->[1] = $b2;
                    $rule_b->{range} = $range;
                }
                else {

                    # Combine ranges of $rule_a and $rule_b.
                    $rule_b->{range} = [ $a1, $b2 ];
                }

                # Mark previous rule as deleted.
                $rule_a->{deleted} = 1;
                $changed = 1;
            }
            $rule_a = $rule_b;
            ($a1, $a2) = ($b1, $b2);
        }
    }

    if ($changed) {
        my @rules;
        for my $rule (@$rules) {

            # Check and remove attribute 'deleted'.
            next if $rule->{deleted};

            # Process rule with joined port ranges.
            # Remove auxiliary attribute {range} from rules.
            if (my $range = delete $rule->{range}) {
                my $proto = $rule->{prt}->{proto};
                my $key   = "$proto $range->[0] $range->[1]";

                # Try to find existing prt with matching range.
                # This is needed for find_objectgroups to work.
                my $new_prt = $prt2obj->{$key};
                if (not $new_prt) {
                    $new_prt = {
                        proto => $proto,
                        range => $range
                    };
                    $prt2obj->{$key} = $new_prt;
                }
                $rule->{prt} = $new_prt;
            }
            push @rules, $rule;
        }
        $rules = \@rules;
    }
    return $rules;
}

# Place those rules first in Cisco ACL that have
# - attribute 'log'
#   because larger rule must not be placed before them,
# - protocols ESP or AH
#   for performance reasons.
# Crypto rules need to have a fixed order,
# otherwise the connection may be lost,
# - if the device is accessed over an IPSec tunnel
# - and we change the ACL incrementally.
sub move_rules_esp_ah {
    my ($acl_info) = @_;
    my $prt2obj = $acl_info->{prt2obj};
    my $prt_esp = $prt2obj->{50};
    my $prt_ah  = $prt2obj->{51};
    $prt_esp or $prt_ah or $acl_info->{has_log} or return;
    for my $what (qw(intf_rules rules)) {
        my $rules = $acl_info->{$what} or next;
        my (@deny_rules, @crypto_rules, @permit_rules);
        for my $rule (@$rules) {
            if ($rule->{deny}) {
                push @deny_rules, $rule;
            }
            elsif ($prt_esp and $rule->{prt} eq $prt_esp
                   or
                   $prt_ah and $rule->{prt} eq $prt_ah
                   or
                   $rule->{log})
            {
                push @crypto_rules, $rule;
            }
            else {
                push @permit_rules, $rule;
            }
        }

        # Sort crypto rules.
        @crypto_rules =
            sort({ my ($s_a, $d_a) = @{$a}{qw(src dst)};
                   my ($s_b, $d_b) = @{$b}{qw(src dst)};
                   !$b->{log} cmp !$a->{log} ||
                   $a->{prt}->{proto} cmp $b->{prt}->{proto} ||
                   $s_a->{ip} cmp $s_b->{ip} || $s_a->{mask} cmp $s_b->{mask} ||
                   $d_a->{ip} cmp $d_b->{ip} || $d_a->{mask} cmp $d_b->{mask} }
                 @crypto_rules);
        $acl_info->{$what} = [ @deny_rules, @crypto_rules, @permit_rules ];
    }
    return;
}

# Add deny and permit rules at device which filters only locally.
sub add_local_deny_rules {
    my ($acl_info, $router_data) = @_;
    my $do_objectgroup = $router_data->{do_objectgroup};
    my ($network_00, $prt_ip) = @{$acl_info}{qw(network_00 prt_ip)};
    my $filter_only = $acl_info->{filter_only};
    my $rules       = $acl_info->{rules};

    my $src_networks =
        $acl_info->{filter_any_src} ? [$network_00] : $filter_only;

    if ($do_objectgroup) {

        my $group_or_single = sub {
            my ($obj_list) = @_;
            if (1 == @$obj_list) {
                return $obj_list->[0];
            }

            # Reuse object-group at all interfaces.
            elsif (my $group = $router_data->{filter_only_group}) {
                return $group;
            }
            else {
                $group = { name => "g$router_data->{obj_group_counter}",
                           elements => $obj_list };
                $router_data->{obj_group_counter}++;
                push @{ $acl_info->{object_groups} }, $group;
                $router_data->{filter_only_group} = $group;
                return $group;
            }
        };
        push(@$rules,
             { deny => 1,
               src => $group_or_single->($src_networks),
               dst => $group_or_single->($filter_only),
               prt => $prt_ip });
    }
    else {
        for my $src (@$src_networks) {
            for my $dst (@$filter_only) {
                push(@$rules,
                     { deny => 1, src => $src, dst => $dst, prt => $prt_ip });
            }
        }
    }
    push @$rules, { src => $network_00, dst => $network_00, prt => $prt_ip };
    return;
}

##############################################################################
# Purpose    : Create a list of IP/mask objects from a hash of IP/mask names.
#              Adjacent IP/mask objects are combined to larger objects.
#              It is assumed, that no duplicate or redundant IP/mask objects
#              are given.
# Parameters : $hash - hash with IP/mask names as keys and
#                      IP/mask objects as values.
#              $ip_net2obj - hash of all known IP/mask objects
# Result     : Returns reference to array of sorted and combined
#              IP/mask objects.
#              Parameter $hash is changed to reflect combined IP/mask objects.
sub combine_adjacent_ip_mask {
    my ($hash, $ip_net2obj) = @_;

    # Convert names to objects.
    # Sort by mask. Adjacent networks will be adjacent elements then.
    my $elements = [
        sort { $a->{ip} cmp $b->{ip} || $a->{mask} cmp $b->{mask} }
        map { $ip_net2obj->{$_} }
        keys %$hash ];

    # Find left and rigth part with identical mask and combine them
    # into next larger network.
    # Compare up to last but one element.
    for (my $i = 0 ; $i < @$elements - 1 ; $i++) {
        my $element1 = $elements->[$i];
        my $element2 = $elements->[$i+1];
        my $mask = $element1->{mask};
        $mask eq $element2->{mask} or next;
        my $prefix = mask2prefix($mask)-1;
        my $up_mask = prefix2mask($prefix);
        my $ip = $element1->{ip};
        ($ip & $up_mask) eq ($element2->{ip} & $up_mask) or next;
        my $up_element = get_ip_obj($ip, $up_mask, $ip_net2obj);

        # Substitute left part by combined network.
        $elements->[$i] = $up_element;

        # Remove right part.
        splice @$elements, $i+1, 1;

        # Add new element and remove left and rigth parts.
        $hash->{$up_element->{name}} = $up_element;
        delete $hash->{$element1->{name}};
        delete $hash->{$element2->{name}};

        if ($i > 0 and $prefix) {
            my $up2_mask = prefix2mask($prefix-1);

            # Check previous network again, if newly created network
            # is right part.
            $i-- if (($ip & $up2_mask) ne $ip);
        }

        # Only one element left.
        # Condition of for-loop isn't effective, because of 'redo' below.
        last if $i >= @$elements - 1;

        # Compare current network again.
        redo;
    }
    return $elements;
}

my $min_object_group_size = 2;

sub find_objectgroups {
    my ($acl_info, $router_data) = @_;
    my $ip_net2obj = $acl_info->{ip_net2obj};

    # Reuse identical groups from different ACLs.
    my $size2first2group = $router_data->{obj_groups_hash} ||= {};
    $router_data->{obj_group_counter} ||= 0;

    # Leave 'intf_rules' untouched, because
    # - these rules are ignored at ASA,
    # - NX-OS needs them individually when optimizing need_protect.
    my $rules = $acl_info->{rules};

    # Find object-groups in src / dst of rules.
    for my $this ('src', 'dst') {
        my $that = $this eq 'src' ? 'dst' : 'src';
        my %group_rule_tree;

        # Find groups of rules with identical
        # deny, src_range, prt, log, src/dst and different dst/src.
        for my $rule (@$rules) {
            my $deny      = $rule->{deny} || '';
            my $that      = $rule->{$that}->{name};
            my $this      = $rule->{$this}->{name};
            my $src_range = $rule->{src_range} || '';
            my $prt       = $rule->{prt};
            my $key       = "$deny,$that,$src_range,$prt";
            if (my $log = $rule->{log}) {
                $key .= ",$log";
            }
            $group_rule_tree{$key}->{$this} = $rule;
        }

        # Find groups >= $min_object_group_size,
        # mark rules belonging to one group.
        for my $href (values %group_rule_tree) {

            # $href is {dst/src => rule, ...}
            keys %$href >= $min_object_group_size or next;

            my $glue = {

                # Indicator, that group has already beed added to some rule.
                active => 0,

                # object-key => rule, ...
                hash => $href
            };

            # All this rules have identical deny, src_range, prt
            # and dst/src and shall be replaced by a single new
            # rule referencing an object group.
            for my $rule (values %$href) {
                $rule->{group_glue} = $glue;
            }
        }

        # Find group with identical elements or define a new one.
        my $get_group = sub {
            my ($hash) = @_;

            # Get sorted and combined list of objects from hash of names.
            my $elements = combine_adjacent_ip_mask($hash, $ip_net2obj);

            # If all elements have been combined into one single network,
            # don't create a group, but take single element as result.
            if (1 == @$elements) {
                return $elements->[0];
            }

            # Use size and first element as keys for efficient hashing.
            my $size  = @$elements;
            my $first = $elements->[0]->{name};

            # Search group with identical elements.
          HASH:
            for my $group (@{ $size2first2group->{$size}->{$first} }) {
                my $href = $group->{hash};

                # Check elements for equality.
                for my $key (keys %$hash) {
                    $href->{$key} or next HASH;
                }

                # Found $group with matching elements.
                return $group;
            }

            # No group found, build new group.
            my $group = { name     => "g$router_data->{obj_group_counter}",
                          elements => $elements,
                          hash     => $hash, };
            $router_data->{obj_group_counter}++;

            # Store group for later printing of its definition.
            push @{ $acl_info->{object_groups} }, $group;
            push(@{ $size2first2group->{$size}->{$first} }, $group);
            return $group;
        };

        # Build new list of rules using object groups.
        my @new_rules;
        for my $rule (@$rules) {
            if (my $glue = delete $rule->{group_glue}) {
                next if $glue->{active};
                $glue->{active} = 1;
                my $group = $get_group->($glue->{hash});
                $rule->{$this} = $group;
            }
            push @new_rules, $rule;
        }
        $rules = \@new_rules;
    }
    $acl_info->{rules} = $rules;
    return;
}

sub add_protect_rules {
    my ($acl_info, $has_final_permit) = @_;
    my $need_protect = $acl_info->{need_protect} or return;
    my ($network_00, $prt_ip) = @{$acl_info}{qw(network_00 prt_ip)};

    # Add deny rules to protect own interfaces.
    # If a rule permits traffic to a directly connected network behind
    # the device, this would accidently permit traffic to an interface
    # of this device as well.

    # To be added deny rule is needless if there is a rule which
    # permits any traffic to the interface.
    # This permit rule can be deleted if there is a permit any any rule.
    my %no_protect;
    my $changed;
    for my $rule (@{ $acl_info->{intf_rules} }) {
        next if $rule->{deny};
        next if $rule->{src} ne $network_00;
        next if $rule->{prt} ne $prt_ip;
        my $dst = $rule->{dst};
        $no_protect{$dst} = 1 if $dst->{need_protect};

        if ($has_final_permit) {
            $rule    = undef;
            $changed = 1;
        }
    }
    if ($changed) {
        $acl_info->{intf_rules} = [ grep { $_ } @{ $acl_info->{intf_rules} } ];
    }

    # Deny rule is needless if there is no such permit rule.
    # Try to optimize this case.
    my %need_protect;
    for my $rule (@{ $acl_info->{rules} }) {
        next if $rule->{deny};
        next if $rule->{prt}->{established};
        my $dst = $rule->{dst};
        my $hash = $dst->{is_supernet_of_need_protect} or next;
        for my $intf (@$need_protect) {
            if ($hash->{$intf}) {
                $need_protect{$intf} = $intf;
            }
        }
    }

    # Protect own interfaces.
    for my $interface (@$need_protect) {
        if (    $no_protect{$interface}
            or  not $need_protect{$interface}
            and not $has_final_permit)
        {
            next;
        }

        push @{ $acl_info->{intf_rules} }, {
            deny => 1,
            src  => $network_00,
            dst  => $interface,
            prt  => $prt_ip
        };
    }
}

# Check if last is rule is 'permit ip any any'.
sub check_final_permit {
    my ($acl_info) = @_;
    my $rules = $acl_info->{rules};
    $rules and @$rules or return;
    my ($net_00, $prt_ip) = @{$acl_info}{qw(network_00 prt_ip)};
    my ($deny, $src, $dst, $prt) = @{ $rules->[-1] }{qw(deny src dst prt)};
    return !$deny && $src eq $net_00 && $dst eq $net_00 && $prt eq $prt_ip;
}

# Add 'deny|permit ip any any' at end of ACL.
sub add_final_permit_deny_rule {
    my ($acl_info) = @_;
    $acl_info->{add_deny} or $acl_info->{add_permit} or return;

    my ($net_00, $prt_ip) = @{$acl_info}{qw(network_00 prt_ip)};
    my $rule = { src => $net_00, dst => $net_00, prt => $prt_ip };
    if ($acl_info->{add_deny}) {
        $rule->{deny} = 1;
    }
    push @{ $acl_info->{rules} }, $rule;

    return;
}

# Returns iptables code for filtering a protocol.
sub iptables_prt_code {
    my ($src_range, $prt) = @_;
    my $proto = $prt->{proto};

    if ($proto eq 'tcp' or $proto eq 'udp') {
        my $port_code = sub {
            my ($range_obj) = @_;
            my ($v1, $v2) = @{ $range_obj->{range} };
            if ($v1 == $v2) {
                return $v1;
            }
            elsif ($v1 == 1 and $v2 == 65535) {
                return '';
            }
            elsif ($v2 == 65535) {
                return "$v1:";
            }
            elsif ($v1 == 1) {
                return ":$v2";
            }
            else {
                return "$v1:$v2";
            }
        };
        my $result = "-p $proto";
        my $sport = $src_range && $port_code->($src_range);
        $result .= " --sport $sport" if $sport;
        my $dport = $port_code->($prt);
        $result .= " --dport $dport" if $dport;
        return $result;
    }
    elsif ($proto eq 'icmp') {
        if (defined(my $type = $prt->{type})) {
            if (defined(my $code = $prt->{code})) {
                return "-p $proto --icmp-type $type/$code";
            }
            else {
                return "-p $proto --icmp-type $type";
            }
        }
        else {
            return "-p $proto";
        }
    }
    else {
        return "-p $proto";
    }
}


# Handle iptables.
#
#sub debug_bintree {
#    my ($tree, $depth) = @_;
#    $depth ||= '';
#    my $ip      = bitstr2ip($tree->{ip});
#    my $mask    = mask2prefix($tree->{mask});
#    my $subtree = $tree->{subtree} ? 'subtree' : '';
#
#    debug($depth, " $ip/$mask $subtree");
#    debug_bintree($tree->{lo}, "${depth}l") if $tree->{lo};
#    debug_bintree($tree->{hi}, "${depth}h") if $tree->{hi};
#    return;
#}

# Nodes are reverse sorted before being added to bintree.
# Redundant nodes are discarded while inserting.
# A node with value of sub-tree S is discarded,
# if some parent node already has sub-tree S.
sub add_bintree;
sub add_bintree {
    my ($tree,    $node)      = @_;
    my ($tree_ip, $tree_mask) = @{$tree}{qw(ip mask)};
    my ($node_ip, $node_mask) = @{$node}{qw(ip mask)};
    my $result;

    # The case where new node is larger than root node will never
    # occur, because nodes are sorted before being added.

    if ($tree_mask lt $node_mask && match_ip($node_ip, $tree_ip, $tree_mask)) {

        # Optimization for this special case:
        # Root of tree has attribute {subtree} which is identical to
        # attribute {subtree} of current node.
        # Node is known to be less than root node.
        # Hence node together with its subtree can be discarded
        # because it is redundant compared to root node.
        # ToDo:
        # If this optimization had been done before merge_subtrees,
        # it could have merged more subtrees.
        if (   not $tree->{subtree}
            or not $node->{subtree}
            or $tree->{subtree} ne $node->{subtree})
        {
            my $prefix = mask2prefix($tree_mask);
            my $mask = prefix2mask($prefix+1);
            my $branch = match_ip($node_ip, $tree_ip, $mask) ? 'lo' : 'hi';
            if (my $subtree = $tree->{$branch}) {
                $tree->{$branch} = add_bintree $subtree, $node;
            }
            else {
                $tree->{$branch} = $node;
            }
        }
        $result = $tree;
    }

    # Create common root for tree and node.
    else {
        while (1) {
            my $prefix = mask2prefix($tree_mask);
            $tree_mask = prefix2mask($prefix-1);
            last if ($node_ip & $tree_mask) eq ($tree_ip & $tree_mask);
        }
        $result = {
            ip   => ($node_ip & $tree_mask),
            mask => $tree_mask
        };
        @{$result}{qw(lo hi)} =
          $node_ip lt $tree_ip ? ($node, $tree) : ($tree, $node);
    }

    # Merge adjacent sub-networks.
  MERGE:
    {
        $result->{subtree} and last;
        my $lo = $result->{lo} or last;
        my $hi = $result->{hi} or last;
        my $prefix = mask2prefix($result->{mask});
        my $mask = prefix2mask($prefix+1);
        $lo->{mask} eq $mask or last;
        $hi->{mask} eq $mask or last;
        $lo->{subtree} and $hi->{subtree} or last;
        $lo->{subtree} eq $hi->{subtree} or last;

        for my $key (qw(lo hi)) {
            $lo->{$key} and last MERGE;
            $hi->{$key} and last MERGE;
        }

#       debug('Merged: ', print_ip $lo->{ip},' ',
#             print_ip $hi->{ip},'/',print_ip $hi->{mask});
        $result->{subtree} = $lo->{subtree};
        delete $result->{lo};
        delete $result->{hi};
    }
    return $result;
}

# Build a binary tree for src/dst objects.
sub gen_addr_bintree {
    my ($elements, $tree) = @_;

    # Sort in reverse order by mask and then by IP.
    my @nodes =
      sort { $b->{mask} cmp $a->{mask} || $b->{ip} cmp $a->{ip} }
      map {
        my ($ip, $mask) = @{$_}{qw(ip mask)};

        # The tree's node is a simplified network object with
        # missing attribute 'name' and extra 'subtree'.
        { ip      => $ip,
          mask    => $mask,
          subtree => $tree->{$_->{name}}
        }
      } @$elements;
    my $bintree = pop @nodes;
    while (my $next = pop @nodes) {
        $bintree = add_bintree $bintree, $next;
    }

    # Add attribute {noop} to node which doesn't add any test to
    # generated rule.
    $bintree->{noop} = 1 if $bintree->{mask} eq $zero_ip;

#    debug_bintree($bintree);
    return $bintree;
}

# Build a tree for src-range/prt objects. Sub-trees for tcp and udp
# will be binary trees. Nodes have attributes {proto}, {range},
# {type}, {code} like protocols (but without {name}).
# Additional attributes for building the tree:
# For tcp and udp:
# {lo}, {hi} for sub-ranges of current node.
# For other protocols:
# {seq} an array of ordered nodes for sub protocols of current node.
# Elements of {lo} and {hi} or elements of {seq} are guaranteed to be
# disjoint.
# Additional attribute {subtree} is set with corresponding subtree of
# protocol object if current node comes from a rule and wasn't inserted
# for optimization.
sub gen_prt_bintree {
    my ($elements, $tree) = @_;

    my $ip_prt;
    my (%top_prt, %sub_prt);

    # Add all protocols directly below protocol 'ip' into hash %top_prt
    # grouped by protocol. Add protocols below top protocols or below
    # other protocols of current set of protocols to hash %sub_prt.
  PRT:
    for my $prt (@$elements) {
        my $proto = $prt->{proto};
        if ($proto eq 'ip') {
            $ip_prt = $prt;
            next PRT;
        }

        my $up = $prt->{up};

        # Check if $prt is sub protocol of any other protocol of
        # current set. But handle direct sub protocols of 'ip' as top
        # protocols.
        while ($up->{up}) {
            if (my $subtree = $tree->{$up->{name}}) {

                # Found sub protocol of current set.
                # Optimization:
                # Ignore the sub protocol if both protocols have
                # identical subtrees.
                # In this case we found a redundant sub protocol.
                if ($tree->{$prt->{name}} ne $subtree) {
                    push @{ $sub_prt{$up} }, $prt;
                }
                next PRT;
            }
            $up = $up->{up};
        }

        # Not a sub protocol (except possibly of IP).
        my $key = $proto =~ /^\d+$/ ? 'proto' : $proto;
        push @{ $top_prt{$key} }, $prt;
    }

    # Collect subtrees for tcp, udp, proto and icmp.
    my @seq;

# Build subtree of tcp and udp protocols.
    #
    # We need not to handle 'tcp established' because it is only used
    # for stateless routers, but iptables is stateful.
    my ($gen_lohitrees, $gen_rangetree);
    $gen_lohitrees = sub {
        my ($prt_aref) = @_;
        if (not $prt_aref) {
            return (undef, undef);
        }
        elsif (@$prt_aref == 1) {
            my $prt = $prt_aref->[0];
            my ($lo, $hi) = $gen_lohitrees->($sub_prt{$prt});
            my $node = {
                proto   => $prt->{proto},
                range   => $prt->{range},
                subtree => $tree->{$prt->{name}},
                lo      => $lo,
                hi      => $hi
            };
            return ($node, undef);
        }
        else {
            my @ranges =
              sort { $a->{range}->[0] <=> $b->{range}->[0] } @$prt_aref;

            # Split array in two halves.
            my $mid   = int($#ranges / 2);
            my $left  = [ @ranges[ 0 .. $mid ] ];
            my $right = [ @ranges[ $mid + 1 .. $#ranges ] ];
            return ($gen_rangetree->($left), $gen_rangetree->($right));
        }
    };
    $gen_rangetree = sub {
        my ($prt_aref) = @_;
        my ($lo, $hi) = $gen_lohitrees->($prt_aref);
        return $lo if not $hi;
        my $proto = $lo->{proto};

        # Take low port from lower tree and high port from high tree.
        my $range = [ $lo->{range}->[0], $hi->{range}->[1] ];

        # Merge adjacent port ranges.
        if (    $lo->{range}->[1] + 1 == $hi->{range}->[0]
            and $lo->{subtree}
            and $hi->{subtree}
            and $lo->{subtree} eq $hi->{subtree})
        {
            my @hilo =
              grep { defined $_ } $lo->{lo}, $lo->{hi}, $hi->{lo}, $hi->{hi};
            if (@hilo <= 2) {

#		debug("Merged: $lo->{range}->[0]-$lo->{range}->[1]",
#		      " $hi->{range}->[0]-$hi->{range}->[1]");
                my $node = {
                    proto   => $proto,
                    range   => $range,
                    subtree => $lo->{subtree}
                };
                $node->{lo} = shift @hilo if @hilo;
                $node->{hi} = shift @hilo if @hilo;
                return $node;
            }
        }
        return (
            {
                proto => $proto,
                range => $range,
                lo    => $lo,
                hi    => $hi
            }
        );
    };
    for my $what (qw(tcp udp)) {
        next if not $top_prt{$what};
        push @seq, $gen_rangetree->($top_prt{$what});
    }

# Add single nodes for numeric protocols.
    if (my $aref = $top_prt{proto}) {
        for my $prt (sort { $a->{proto} <=> $b->{proto} } @$aref) {
            my $node = { proto => $prt->{proto}, subtree => $tree->{$prt->{name}} };
            push @seq, $node;
        }
    }

# Build subtree of icmp protocols.
    if (my $icmp_aref = $top_prt{icmp}) {
        my %type2prt;
        my $icmp_any;

        # If one protocol is 'icmp any' it is the only top protocol,
        # all other icmp protocols are sub protocols.
        if (not defined $icmp_aref->[0]->{type}) {
            $icmp_any  = $icmp_aref->[0];
            $icmp_aref = $sub_prt{$icmp_any};
        }

        # Process icmp protocols having defined type and possibly defined code.
        # Group protocols by type.
        for my $prt (@$icmp_aref) {
            my $type = $prt->{type};
            push @{ $type2prt{$type} }, $prt;
        }

        # Parameter is array of icmp protocols all having
        # the same type and different but defined code.
        # Return reference to array of nodes sorted by code.
        my $gen_icmp_type_code_sorted = sub {
            my ($aref) = @_;
            [
                map {
                    {
                        proto   => 'icmp',
                        type    => $_->{type},
                        code    => $_->{code},
                        subtree => $tree->{$_->{name}}
                    }
                  }
                  sort { $a->{code} <=> $b->{code} } @$aref
            ];
        };

        # For collecting subtrees of icmp subtree.
        my @seq2;

        # Process grouped icmp protocols having the same type.
        for my $type (sort { $a <=> $b } keys %type2prt) {
            my $aref2 = $type2prt{$type};
            my $node2;

            # If there is more than one protocol,
            # all have same type and defined code.
            if (@$aref2 > 1) {
                my $seq3 = $gen_icmp_type_code_sorted->($aref2);

                # Add a node 'icmp type any' as root.
                $node2 = {
                    proto => 'icmp',
                    type  => $type,
                    seq   => $seq3,
                };
            }

            # One protocol 'icmp type any'.
            else {
                my $prt = $aref2->[0];
                $node2 = {
                    proto   => 'icmp',
                    type    => $type,
                    subtree => $tree->{$prt->{name}}
                };
                if (my $aref3 = $sub_prt{$prt}) {
                    $node2->{seq} = $gen_icmp_type_code_sorted->($aref3);
                }
            }
            push @seq2, $node2;
        }

        # Add root node for icmp subtree.
        my $node;
        if ($icmp_any) {
            $node = {
                proto   => 'icmp',
                seq     => \@seq2,
                subtree => $tree->{$icmp_any->{name}}
            };
        }
        elsif (@seq2 > 1) {
            $node = { proto => 'icmp', seq => \@seq2 };
        }
        else {
            $node = $seq2[0];
        }
        push @seq, $node;
    }

# Add root node for whole tree.
    my $bintree;
    if ($ip_prt) {
        $bintree = {
            proto   => 'ip',
            seq     => \@seq,
            subtree => $tree->{$ip_prt->{name}}
        };
    }
    elsif (@seq > 1) {
        $bintree = { proto => 'ip', seq => \@seq };
    }
    else {
        $bintree = $seq[0];
    }

    # Add attribute {noop} to node which doesn't need any test in
    # generated chain.
    $bintree->{noop} = 1 if $bintree->{proto} eq 'ip';
    return $bintree;
}

sub find_chains {
    my ($acl_info, $router_data) = @_;
    my $rules      = $acl_info->{rules};
    my $ip_net2obj = $acl_info->{ip_net2obj};
    my $prt2obj    = $acl_info->{prt2obj};
    my %ref_type = (
        src       => $ip_net2obj,
        dst       => $ip_net2obj,
        src_range => $prt2obj,
        prt       => $prt2obj,
    );

    my $prt_ip     = $prt2obj->{ip};
    my $prt_icmp   = $prt2obj->{icmp};
    my $prt_tcp    = $prt2obj->{'tcp 1 65535'};
    my $prt_udp    = $prt2obj->{'udp 1 65535'};
    my $network_00 = $acl_info->{network_00};

    # For generating names of chains.
    # Initialize if called first time.
    $router_data->{chain_counter} ||= 1;

    # Set {action} attribute in $rule, so we can handle all properties
    # of a rule in unified manner.
    # Change {src_range} attribute.
    for my $rule (@$rules) {
        if (!$rule->{action}) {
            $rule->{action} = $rule->{deny} ? 'deny' : 'permit';
        }
        my $src_range = $rule->{src_range};
        if (not $src_range) {
            my $proto = $rule->{prt}->{proto};

            # Specify protocols tcp, udp, icmp in
            # {src_range}, to get more efficient chains.
            $src_range =
                $proto eq 'tcp'  ? $prt_tcp
              : $proto eq 'udp'  ? $prt_udp
              : $proto eq 'icmp' ? $prt_icmp
              :                    $prt_ip;
            $rule->{src_range} = $src_range;
        }
    }

    my %cache;

#    my $print_tree;
#    $print_tree = sub {
#        my ($tree, $order, $depth) = @_;
#        for my $name (keys %$tree) {
#
#            debug(' ' x $depth, $name);
#            if ($depth < $#$order) {
#                $print_tree->($tree->{$name}, $order, $depth + 1);
#            }
#        }
#    };

    my $insert_bintree = sub {
        my ($tree, $order, $depth) = @_;
        my $key      = $order->[$depth];
        my $ref2x    = $ref_type{$key};
        my @elements = map { $ref2x->{$_} } keys %$tree;

        # Put prt/src/dst objects at the root of some subtree into a
        # (binary) tree. This is used later to convert subsequent tests
        # for ip/mask or port ranges into more efficient nested chains.
        my $bintree;
        if ($ref2x eq $ip_net2obj) {
            $bintree = gen_addr_bintree(\@elements, $tree);
        }
        else {    # $ref2x eq $prt2obj
            $bintree = gen_prt_bintree(\@elements, $tree);
        }
        return $bintree;
    };

    # Used by $merge_subtrees1 to find identical subtrees.
    # Use hash for efficient lookup.
    my %depth2size2subtrees;
    my %subtree2bintree;

    # Find and merge identical subtrees.
    my $merge_subtrees1 = sub {
        my ($tree, $order, $depth) = @_;

      SUBTREE:
        for my $subtree (values %$tree) {
            my @keys = keys %$subtree;
            my $size = @keys;

            # Find subtree with identical keys and values;
          FIND:
            for my $subtree2 (@{ $depth2size2subtrees{$depth}->{$size} }) {
                for my $key (@keys) {
                    if (not $subtree2->{$key}
                        or $subtree2->{$key} ne $subtree->{$key})
                    {
                        next FIND;
                    }
                }

                # Substitute current subtree with found subtree.
                $subtree = $subtree2bintree{$subtree2};
                next SUBTREE;

            }

            # Found a new subtree.
            push @{ $depth2size2subtrees{$depth}->{$size} }, $subtree;
            $subtree = $subtree2bintree{$subtree} =
              $insert_bintree->($subtree, $order, $depth + 1);
        }
    };

    my $merge_subtrees = sub {
        my ($tree, $order) = @_;

        # Process leaf nodes first.
        for my $href1 (values %$tree) {
            for my $href2 (values %$href1) {
                $merge_subtrees1->($href2, $order, 2);
            }
        }

        # Process nodes next to leaf nodes.
        for my $href (values %$tree) {
            $merge_subtrees1->($href, $order, 1);
        }

        # Process nodes next to root.
        $merge_subtrees1->($tree, $order, 0);
        return $insert_bintree->($tree, $order, 0);
    };

    # Add new chain to current router.
    my $new_chain = sub {
        my ($rules) = @_;
        my $counter = $router_data->{chain_counter}++;
        my $chain   = { name  => "c$counter", rules => $rules, };
        push @{ $router_data->{chains} }, $chain;
        return $chain;
    };

    my $gen_chain;
    $gen_chain = sub {
        my ($tree, $order, $depth) = @_;
        my $key = $order->[$depth];
        my @rules;

        # We need the original value later.
        my $bintree = $tree;
        while (1) {
            my ($hi, $lo, $seq, $subtree) =
              @{$bintree}{qw(hi lo seq subtree)};
            $seq = undef if $seq and not @$seq;
            if (not $seq) {
                push @$seq, $hi if $hi;
                push @$seq, $lo if $lo;
            }
            if ($subtree) {

#               if($order->[$depth+1]&&
#                  $order->[$depth+1] =~ /^(src|dst)$/) {
#                   debug($order->[$depth+1]);
#                   debug_bintree($subtree);
#               }
                my $rules = $cache{$subtree};
                if (not $rules) {
                    $rules =
                      $depth + 1 >= @$order
                      ? [ { action => $subtree } ]
                      : $gen_chain->($subtree, $order, $depth + 1);
                    if (@$rules > 1 and not $bintree->{noop}) {
                        my $chain = $new_chain->($rules);
                        $rules = [ { action => $chain, goto => 1 } ];
                    }
                    $cache{$subtree} = $rules;
                }

                my @add_keys;

                # Don't use "goto", if some tests for sub-nodes of
                # $subtree are following.
                push @add_keys, (goto => 0)        if $seq;
                push @add_keys, ($key => $bintree) if not $bintree->{noop};
                if (@add_keys) {

                    # Create a copy of each rule because we must not change
                    # the original cached rules.
                    push @rules, map {
                        { (%$_, @add_keys) }
                    } @$rules;
                }
                else {
                    push @rules, @$rules;
                }
            }
            last if not $seq;

            # Take this value in next iteration.
            $bintree = pop @$seq;

            # Process remaining elements.
            for my $node (@$seq) {
                my $rules = $gen_chain->($node, $order, $depth);
                push @rules, @$rules;
            }
        }
        if (@rules > 1 and not $tree->{noop}) {

            # Generate new chain. All elements of @seq are
            # known to be disjoint. If one element has matched
            # and branched to a chain, then the other elements
            # need not be tested again. This is implemented by
            # calling the chain using '-g' instead of the usual '-j'.
            my $chain = $new_chain->(\@rules);
            return [ { action => $chain, goto => 1, $key => $tree } ];
        }
        else {
            return \@rules;
        }
    };

    # Build rule trees. Generate and process separate tree for
    # adjacent rules with same action.
    my @rule_trees;
    my %tree2order;
    if (@$rules) {
        my $prev_action = $rules->[0]->{action};

        # Special rule as marker, that end of rules has been reached.
        push @$rules, { action => 0 };
        my $start = my $i = 0;
        my %count;
        while (1) {
            my $rule   = $rules->[$i];
            my $action = $rule->{action};
            if ($action eq $prev_action) {

                # Count, which key has the largest number of
                # different values.
                for my $what (qw(src dst src_range prt)) {
                    $count{$what}{ $rule->{$what} } = 1;
                }
                $i++;
            }
            else {

                # Use key with smaller number of different values
                # first in rule tree. This gives smaller tree and
                # fewer tests in chains.
                my @test_order =
                  sort { keys %{ $count{$a} } <=> keys %{ $count{$b} } }
                  qw(src_range dst prt src);
                my $rule_tree;
                my $end = $i - 1;
                for (my $j = $start ; $j <= $end ; $j++) {
                    my $rule = $rules->[$j];
                    my ($action, $t1, $t2, $t3, $t4) =
                      @{$rule}{ 'action', @test_order };
                    ($t1, $t2, $t3, $t4) =
                        map { $_->{name} } ($t1, $t2, $t3, $t4);
                    $rule_tree->{$t1}->{$t2}->{$t3}->{$t4} = $action;
                }
                push @rule_trees, $rule_tree;

#   	    debug(join ', ', @test_order);
                $tree2order{$rule_tree} = \@test_order;
                last if not $action;
                $start       = $i;
                $prev_action = $action;
            }
        }
        @$rules = ();
    }

    for (my $i = 0 ; $i < @rule_trees ; $i++) {
        my $tree  = $rule_trees[$i];
        my $order = $tree2order{$tree};

#       $print_tree->($tree, $order, 0);
        $tree = $merge_subtrees->($tree, $order);
        my $result = $gen_chain->($tree, $order, 0);

        # Goto must not be used in last rule of rule tree which is
        # not the last tree.
        if ($i != $#rule_trees) {
            my $rule = $result->[-1];
            delete $rule->{goto};
        }

        # Postprocess rules: Add missing attributes prt, src, dst
        # with no-op values.
        for my $rule (@$result) {
            $rule->{src} ||= $network_00;
            $rule->{dst} ||= $network_00;
            my $prt     = $rule->{prt};
            my $src_range = $rule->{src_range};
            if (not $prt and not $src_range) {
                $rule->{prt} = $prt_ip;
            }
            elsif (not $prt) {
                $rule->{prt} =
                    $src_range->{proto} eq 'tcp'  ? $prt_tcp
                  : $src_range->{proto} eq 'udp'  ? $prt_udp
                  : $src_range->{proto} eq 'icmp' ? $prt_icmp
                  :                                 $prt_ip;
            }
        }
        push @$rules, @$result;
    }
    $acl_info->{rules} = $rules;
    return;
}

# Given an IP and mask, return its address
# as "x.x.x.x/x" or "x.x.x.x" if prefix == 32 (128, if IPv6 option set).
sub prefix_code {
    my ($ip_net) = @_;
    my ($ip, $mask) = @{$ip_net}{qw(ip mask)};
    my $ip_code     = bitstr2ip($ip);
    if ($mask eq $max_ip) {
        return $ip_code;
    }
    else {
        my $prefix_code = mask2prefix($mask);
        return "$ip_code/$prefix_code";
    }
}

# Print chains of iptables.
# Objects have already been normalized to ip/mask pairs.
# NAT has already been applied.
sub print_chains {
    my ($router_data) = @_;
    my $chains = $router_data->{chains};
    @$chains or return;

    my $acl_info   = $router_data->{acls}->[0];
    my $prt2obj    = $acl_info->{prt2obj};
    my $prt_ip     = $prt2obj->{ip};
    my $prt_icmp   = $prt2obj->{icmp};
    my $prt_tcp    = $prt2obj->{'tcp 1 65535'};
    my $prt_udp    = $prt2obj->{'udp 1 65535'};

    # Declare chain names.
    for my $chain (@$chains) {
        my $name = $chain->{name};
        print ":$name -\n";
    }

    # Define chains.
    for my $chain (@$chains) {
        my $name   = $chain->{name};
        my $prefix = "-A $name";

#	my $steps = my $accept = my $deny = 0;
        for my $rule (@{ $chain->{rules} }) {
            my $action = $rule->{action};
            my $action_code =
                ref($action)        ? $action->{name}
              : $action eq 'permit' ? 'ACCEPT'
              :                       'droplog';

            # Calculate maximal number of matches if
            # - some rules matches (accept) or
            # - all rules don't match (deny).
#	    $steps += 1;
#	    if ($action eq 'permit') {
#		$accept = max($accept, $steps);
#	    }
#	    elsif ($action eq 'deny') {
#		$deny = max($deny, $steps);
#	    }
#	    elsif ($rule->{goto}) {
#		$accept = max($accept, $steps + $action->{a});
#	    }
#	    else {
#		$accept = max($accept, $steps + $action->{a});
#		$steps += $action->{d};
#	    }

            my $jump = $rule->{goto} ? '-g' : '-j';
            my $result = "$jump $action_code";
            if (my $src = $rule->{src}) {
                if ($src->{mask} ne $zero_ip) {
                    $result .= ' -s ' . prefix_code($src);
                }
            }
            if (my $dst = $rule->{dst}) {
                if ($dst->{mask} ne $zero_ip) {
                    $result .= ' -d ' . prefix_code($dst);
                }
            }
          ADD_PROTO:
            {
                my $src_range = $rule->{src_range};
                my $prt       = $rule->{prt};
                last ADD_PROTO if not $src_range and not $prt;
                last ADD_PROTO if $prt and $prt->{proto} eq 'ip';
                if (not $prt) {
                    last ADD_PROTO if $src_range->{proto} eq 'ip';
                    $prt =
                        $src_range->{proto} eq 'tcp'  ? $prt_tcp
                      : $src_range->{proto} eq 'udp'  ? $prt_udp
                      : $src_range->{proto} eq 'icmp' ? $prt_icmp
                      :                                 $prt_ip;
                }

#               debug("c ",print_rule $rule) if not $src_range or not $prt;
                $result .= ' ' . iptables_prt_code($src_range, $prt);
            }
            print "$prefix $result\n";
        }

#	$deny = max($deny, $steps);
#	$chain->{a} = $accept;
#	$chain->{d} = $deny;
#	print "# Max tests: Accept: $accept, Deny: $deny\n";
    }

    # Empty line as delimiter.
    print "\n";
    return;
}

sub iptables_acl_line {
    my ($rule, $prefix) = @_;
    my ($action, $src, $dst, $src_range, $prt) =
      @{$rule}{qw(action src dst src_range prt)};
    my $action_code =
        ref($action)        ? $action->{name}
      : $action eq 'permit' ? 'ACCEPT'
      :                       'droplog';
    my $jump = $rule->{goto} ? '-g' : '-j';
    my $result = "$prefix $jump $action_code";
    if ($src->{mask} ne $zero_ip) {
        $result .= ' -s ' . prefix_code($src);
    }
    if ($dst->{mask} ne $zero_ip) {
        $result .= ' -d ' . prefix_code($dst);
    }
    if ($prt->{proto} ne 'ip') {
        $result .= ' ' . iptables_prt_code($src_range, $prt);
    }
    print "$result\n";
    return;
}

sub print_iptables_acl {
    my ($acl_info) = @_;
    my $name = $acl_info->{name};
    print ":$name -\n";
    my $rules = $acl_info->{rules};
    my $intf_prefix = "-A $name";
    for my $rule (@$rules) {
        iptables_acl_line($rule, $intf_prefix);
    }
}

sub expand_rule {
    my ($rule) = @_;
    my $src_list = $rule->{src};
    my $dst_list = $rule->{dst};
    my $prt_list = $rule->{prt};
    my @expanded;
    for my $src (@$src_list) {
        for my $dst (@$dst_list) {
            for my $prt (@$prt_list) {
                push @expanded, { %$rule,
                                  src => $src, dst => $dst, prt => $prt };
            }
        }
    }
    return \@expanded;
}

sub convert_rule_objects {
    my ($acl_info) = @_;
    my $ip_net2obj = $acl_info->{ip_net2obj};
    my $prt2obj    = $acl_info->{prt2obj};

    for my $what (qw(intf_rules rules)) {
        my $rules = $acl_info->{$what} or next;
        my @expanded;
        for my $rule (@$rules) {
            if ($rule->{log}) {
                $acl_info->{has_log} = 1;
            }
            my $src_list = $rule->{src};
            for my $ip_net (@$src_list) {
                $ip_net = $ip_net2obj->{$ip_net} ||= create_ip_obj($ip_net);
            }
            my $dst_list = $rule->{dst};
            for my $ip_net (@$dst_list) {
                $ip_net = $ip_net2obj->{$ip_net} ||= create_ip_obj($ip_net);
            }
            my $prt_list = $rule->{prt};
            for my $prt (@$prt_list) {
                $prt = $prt2obj->{$prt} ||= create_prt_obj($prt);
            }
            if (my $prt = $rule->{src_range}) {
                $rule->{src_range} =
                    $prt2obj->{$prt} ||= create_prt_obj($prt);
            }
            push @expanded, @{ expand_rule($rule) };
        }
        $acl_info->{$what} = \@expanded;
    }
}

sub prepare_acls {
    my ($path) = @_;
    my $router_data = from_json(read_file($path));
    my ($model, $acls, $filter_only, $do_objectgroup) =
        @{$router_data}{qw(model acls filter_only do_objectgroup)};

    for my $acl_info (@$acls) {

        # Process networks and protocols of each interface individually,
        # because relation between networks may be changed by NAT.
        my $ip_net2obj = $acl_info->{ip_net2obj} = {};
        my $prt2obj    = $acl_info->{prt2obj}    = {};

        if ($filter_only) {
            $acl_info->{filter_only} = [
                map { $ip_net2obj->{$_} ||= create_ip_obj($_); }
                @$filter_only ]
        }

        convert_rule_objects($acl_info);

        for my $what (qw(opt_networks no_opt_addrs need_protect)) {
            if (my $list = $acl_info->{$what}) {
                for my $ip_net (@$list) {
                    my $obj = $ip_net2obj->{$ip_net} ||= create_ip_obj($ip_net);
                    $obj->{$what} = $obj;
                    $ip_net = $obj;
                }
            }
        }

        setup_ip_net_relation($ip_net2obj);
        $acl_info->{network_00} = $ip_net2obj->{get_net00_addr()};

        if (my $need_protect = $acl_info->{need_protect}) {
            mark_supernets_of_need_protect($need_protect);
        }
        if ($model eq 'Linux') {
            add_tcp_udp_icmp($prt2obj);
        }

        setup_prt_relation($prt2obj);
        $acl_info->{prt_ip} = $prt2obj->{ip};

        if ($model eq 'Linux') {
            find_chains($acl_info, $router_data);
        }
        else {
            for my $what (qw(intf_rules rules)) {
                my $rules = $acl_info->{$what} or next;
                $rules = optimize_rules($rules, $acl_info);

                # Join adjacent port ranges. This must be called after
                # local optimization, because protocols will be
                # overlapping again after joining.
                $rules = join_ranges($rules, $prt2obj);
                $acl_info->{$what} = $rules;
            }
            move_rules_esp_ah($acl_info);

            my $has_final_permit = check_final_permit($acl_info);
            my $add_permit       = $acl_info->{add_permit};
            add_protect_rules($acl_info, $has_final_permit || $add_permit);
            if ($do_objectgroup and not $acl_info->{is_crypto_acl}) {
                find_objectgroups($acl_info, $router_data);
            }
            if ($filter_only and not $add_permit) {
                add_local_deny_rules($acl_info, $router_data);
            }
            elsif (not $has_final_permit) {
                add_final_permit_deny_rule($acl_info);
            }
        }
    }
    return $router_data;
}

# Given IP or group object, return its address in Cisco syntax.
sub cisco_acl_addr {
    my ($obj, $model) = @_;
    my ($ip, $mask) = @{$obj}{qw(ip mask)};

    # Object group.
    if (not defined $ip) {
        my $keyword = $model eq 'NX-OS' ? 'addrgroup' : 'object-group';
        return "$keyword $obj->{name}";
    }
    elsif ($mask eq $zero_ip) {
        if ($model eq 'ASA') {
            return length($mask) == 4 ? 'any4' : 'any6';
        }
        else {
            return 'any';
        }
    }
    elsif ($model eq 'NX-OS') {
        return $obj->{name};
    }
    else {
        my $ip_code = bitstr2ip($ip);
        if ($max_ip eq $mask) {
            return "host $ip_code";
        }
        else {

            # Inverse mask bits.
            $mask = ~$mask if $model =~ /^(:?NX-OS|IOS)$/;
            my $mask_code = bitstr2ip($mask);
            return "$ip_code $mask_code";
        }
    }
}

sub print_object_groups {
    my ($groups, $model) = @_;
    my $keyword = $model eq 'NX-OS'
                ? 'object-group ip address'
                : 'object-group network';
    for my $group (@$groups) {

        my $numbered = 10;
        print "$keyword $group->{name}\n";
        for my $element (@{ $group->{elements} }) {

            # Reject network with mask = 0 in group.
            # This occurs if optimization didn't work correctly.
            $zero_ip eq $element->{mask}
                and fatal_err("Unexpected network with mask 0 in object-group");
            my $adr = cisco_acl_addr($element, $model);
            if ($model eq 'NX-OS') {
                print " $numbered $adr\n";
                $numbered += 10;
            }
            else {
                print " network-object $adr\n";
            }
        }
    }
}

# Returns 3 values for building a Cisco ACL:
# permit <val1> <src> <val2> <dst> <val3>
sub cisco_prt_code {
    my ($src_range, $prt) = @_;
    my $proto = $prt->{proto};

    if ($proto eq 'ip') {
        return ('ip', undef, undef);
    }
    elsif ($proto eq 'tcp' or $proto eq 'udp') {
        my $port_code = sub {
            my ($range_obj) = @_;
            my ($v1, $v2) = @{ $range_obj->{range} };
            if ($v1 == $v2) {
                return ("eq $v1");
            }
            elsif ($v1 == 1 and $v2 == 65535) {
                return (undef);
            }
            elsif ($v2 == 65535) {
                return 'gt ' . ($v1 - 1);
            }
            elsif ($v1 == 1) {
                return 'lt ' . ($v2 + 1);
            }
            else {
                return ("range $v1 $v2");
            }
        };
        my $dst_prt = $port_code->($prt);
        if ($prt->{established}) {
            # uncoverable branch true
            if (defined $dst_prt) {
                $dst_prt .= ' established';	# uncoverable statement
            }
            else {
                $dst_prt = 'established';
            }
        }
        my $src_prt = $src_range && $port_code->($src_range);
        return ($proto, $src_prt, $dst_prt);
    }
    elsif ($proto eq 'icmp') {
        if (defined(my $type = $prt->{type})) {
            if (defined(my $code = $prt->{code})) {
                return ($proto, undef, "$type $code");
            }
            else {
                return ($proto, undef, $type);
            }
        }
        else {
            return ($proto, undef, undef);
        }
    }
    else {
        return ($proto, undef, undef);
    }
}

sub print_asa_std_acl {
    my ($acl_info, $model) = @_;
    my $rules  = $acl_info->{rules};
    my $name   = $acl_info->{name};
    my $prefix = "access-list $name standard";
    for my $rule (@$rules) {
        my ($deny, $src) = @{$rule}{qw(deny src)};
        my $action = $deny ? 'deny' : 'permit';
        my $result = "$prefix $action";
        $result .= ' ' .  cisco_acl_addr($src, $model);
        print "$result\n";
    }
}

sub print_cisco_acl {
    my ($acl_info, $router_data) = @_;
    my $model = $router_data->{model};

    if ($acl_info->{is_std_acl}) {
        print_asa_std_acl($acl_info, $model);
        return;
    }

    my $intf_rules = $acl_info->{intf_rules} || [];
    my $rules = $acl_info->{rules};
    my $name = $acl_info->{name};
    my $numbered = 10;
    my $prefix;
    if ($model eq 'IOS') {
        $prefix = '';
        print "ip access-list extended $name\n";
    }
    elsif ($model eq 'NX-OS') {
        $prefix = '';
        print "ip access-list $name\n";
    }
    elsif ($model eq 'ASA') {
        $prefix = "access-list $name extended";
    }

    for my $rule (@$intf_rules, @$rules) {
        my ($deny, $src, $dst, $src_range, $prt) =
          @{$rule}{qw(deny src dst src_range prt)};
        my $action = $deny ? 'deny' : 'permit';
        my ($proto_code, $src_port_code, $dst_port_code) =
          cisco_prt_code($src_range, $prt);
        my $result = "$prefix $action $proto_code";
        $result .= ' ' . cisco_acl_addr($src, $model);
        $result .= " $src_port_code" if defined $src_port_code;
        $result .= ' ' . cisco_acl_addr($dst, $model);
        $result .= " $dst_port_code" if defined $dst_port_code;

        if (my $log = $rule->{log} || $deny && $router_data->{log_deny}) {
            $result .= " $log";
        }

        # Add line numbers.
        if ($model eq 'NX-OS') {
            $result = " $numbered$result";
            $numbered += 10;
        }
        print "$result\n";
    }
    return;
}

sub print_acl {
    my ($acl_info, $router_data) = @_;
    my $model = $router_data->{model};

    if ($model eq 'Linux') {

        # Print all sub-chains at once before first toplevel chain is printed.
        if ($router_data->{chains}) {
            print_chains($router_data);
            delete $router_data->{chains};
        }
        print_iptables_acl($acl_info);
    }
    else {
        if (my $groups = $acl_info->{object_groups}) {
            print_object_groups($groups, $model);
        }
        print_cisco_acl($acl_info, $router_data);
    }
}

sub print_combined {
    my ($config, $router_data, $out_path) = @_;

    # Redirect print statements to $out_path.
    ## no critic (RequireBriefOpen)
    open(my $out_fd, '>', $out_path)
        or fatal_err("Can't open $out_path for writing: $!");
    select $out_fd;

    my $acls = $router_data->{acls};
    my %acl_hash = map { $_->{name} => $_ } @$acls;

    # Print config and insert printed ACLs at "#insert <name>" markers.
    for my $line (@$config) {

        # Print ACL.
        if (my ($acl_name) = ($line =~ /^#insert (.*)\n$/)) {
            my $acl_info = $acl_hash{$acl_name} or
                fatal_err("Unexpected ACL $acl_name");
            print_acl($acl_info, $router_data);
        }

        # Print unchanged config line.
        else {
            print $line;
        }
    }

    select STDOUT;
    close $out_fd or fatal_err("Can't close $out_path: $!");
    ## use critic

    return;
}

# Try to use pass2 file from previous run.
# If identical files with extension .config and .rules
# exist in directory .prev/, then use copy.
sub try_prev {
    my ($device_path, $dir, $prev) = @_;
    -d $prev or return;
    my $prev_file = "$prev/$device_path";
    -f $prev_file or return;
    my $code_file = "$dir/$device_path";
    for my $ext (qw(config rules)) {
        my $pass1name = "$code_file.$ext";
        my $pass1prev = "$prev_file.$ext";
        -f $pass1prev or return;
        system("cmp -s $pass1name $pass1prev") == 0 or return;
    }
    system("cp -p $prev_file $code_file") == 0 or return;

    # File was found and copied successfully.
    diag_msg("Reused .prev/$device_path") if SHOW_DIAG;
    return 1;
}

sub pass2_file {
    my ($device_path, $dir) = @_;
    my $file = "$dir/$device_path";
    local $config->{ipv6} = $device_path =~ /^ipv6/;
    init_prefix_len;
    init_mask_prefix_lookups;
    init_zero_and_max_ip;

#   debug "building $device_path";
    my $router_data = prepare_acls("$file.rules");
    my $config = read_file_lines("$file.config");
    print_combined($config, $router_data, $file);
}

# Start $code in background.
sub background {
    my ($code, @args) = @_;
    my $pid = fork();
    defined $pid or die "Can't fork:$!";
    if (0 == $pid) {
        $code->(@args);
        exit;
    }
}

sub apply_concurrent {
    my ($concurrent, $device_names_fh, $dir, $prev) = @_;

    my $workers_left = $concurrent;
    my $errors;
    my $reused = 0;
    my $generated = 0;
    my $check_status = sub {
        if ($?) {
            $errors++;			# uncoverable statement
        }
        else {
            $generated++;
        }
    };

    # Read to be processed files either from STDIN or from file.
    # Process with $concurrent background jobs.
    # Error messages of background jobs not catched,
    # but send directly to STDERR.
    while(my $device_path = <$device_names_fh>) {
        chomp $device_path;

        if (try_prev($device_path, $dir, $prev)) {
            $reused++;
        }

        # Process sequentially.
        elsif (1 >= $concurrent) {
            pass2_file($device_path, $dir);
            $generated++;
        }

        # Start concurrent jobs at beginning.
        elsif (0 < $workers_left) {
            background(\&pass2_file, $device_path, $dir);
            $workers_left--;
        }

        # Start next job, after some job has finished.
        else {
            my $pid = wait();
            if ($pid != -1) {
                $check_status->();
            }
            background(\&pass2_file, $device_path, $dir);
        }
    }

    # Wait for all jobs to be finished.
    while (1) {
        my $pid = wait();
        last if -1 == $pid;
        $check_status->();
    }

    $errors and die "Failed\n";
    if ($generated) {
        info("Generated files for $generated devices");
    }
    if ($reused) {
        info("Reused $reused files from previous run");
    }
}

sub pass2 {
    my ($dir) = @_;
    my $prev = "$dir/.prev";

    ## no critic (RequireBriefOpen)
    my $from_pass1;
    if ($config->{pipe}) {
        open($from_pass1, '<&STDIN') or
            fatal_err("Can't open STDIN for reading: $!");
    }
    else {
        my $devlist = "$dir/.devlist";
        open($from_pass1, '<', $devlist) or
            fatal_err("Can't open $devlist for reading: $!");
    }
    ## use critic

    my $concurrent = $config->{concurrency_pass2};
    apply_concurrent($concurrent, $from_pass1, $dir, $prev);

    # Remove directory '.prev' created by pass1
    # or remove symlink '.prev' created by newpolicy.pl.
    my $has_prev = -d $prev;
    if ($has_prev) {
        system("rm -rf $prev") == 0 or fatal_err("Can't remove $prev: $!");
    }
}

# Generate code files from *.config and *.rules files.
sub compile {
    my ($args) = @_;
    ($config, undef, my $dir) = get_args($args);
    if ($dir) {
        $start_time = $config->{start_time} || time();
        pass2($dir);
        progress('Finished');
    }
}

1;
