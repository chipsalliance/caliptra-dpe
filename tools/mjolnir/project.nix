# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
{
  name = "Caliptra DPE";
  repoName = "caliptra-dpe";
  repoUrl = "https://github.com/chipsalliance/caliptra-dpe.git";
  threatModel = ./threat_model.md;
  outputDir = "./tools/mjolnir/results";
  workspaceDir = "./tools/mjolnir/workspace";

  defaultModel = "gemini-3.6-flash";
  defaultProvider = "adk";
  defaultBatchSize = 64;
  defaultExtensions = [ "rs" "go" ];
}
