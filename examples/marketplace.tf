# Install marketplace packs
resource "cortex_marketplace_pack" "base_pack" {
  pack_id = "Base"
}

resource "cortex_marketplace_pack" "common_scripts" {
  pack_id = "CommonScripts"
  version = "1.13.38"
}

resource "cortex_marketplace_pack" "common_types" {
  pack_id = "CommonTypes"
}

resource "cortex_marketplace_pack" "common_playbooks" {
  pack_id = "CommonPlaybooks"
}
