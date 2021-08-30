..
      This work is licensed under a Creative Commons Attribution 3.0 Unported
      License.

      http://creativecommons.org/licenses/by/3.0/legalcode

      Convention for heading levels in Neutron devref:
      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4
      (Avoid deeper levels because they do not render well.)

===================================
Design of OVN Agent with BGP Driver
===================================

Purpose
-------

Overview
--------

With the increment of virtualized/containerized workloads it is becoming more
and more common to use pure layer-3 Spine and Leaf network deployments at
datacenters. There are several benefits of this, such as reduced complexity at
scale, reduced failures domains, limiting broadcast traffic, among others.

Proposed Solution
-----------------

OVN SB DB Events
~~~~~~~~~~~~~~~~

Driver Logic
~~~~~~~~~~~~

Traffic flow
~~~~~~~~~~~~

Agent deployment
~~~~~~~~~~~~~~~~