# Manito Networks Flow Analyzer - Packaged for Kubernetes

Premise
---

I have been using the Manito Networks FlowAnalyzer project for quite a while to do netflow capture from some of my infrastructure.

I wanted to package it as a Kubernetes manifest so it could be deployed easier.

Notes
---

* Only Netflow v9 is implemented in v1.0.0
* No security is enabled on ElasticSearch or Kibana
  * ElasticSearch isn't given a NodeIP, Kibana and Netflow are.
* This was mostly to play around with it on an already-existing Kubernetes cluster.
  * Thus, no guarantees on its fitness for your project.
* You may want to use a different service method than NodeIP, since tracking the port to reconfigure your devices is a pain.

Source
---
Everything is derived from the original project here:

https://gitlab.com/thart/flowanalyzer

Original copyright
---
Copyright (c) 2017, Manito Networks, LLC
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of flowanalyzer nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

