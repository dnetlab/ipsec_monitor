
include $(TOPDIR)/rules.mk

PKG_NAME:=ipsec-monitor
PKG_VERSION:=1.0

PKG_BUILD_DIR:= $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/ipsec-monitor
	SECTION  := net
 	CATEGORY := Network
	TITLE    := ipsec monitor tools
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

define Package/ipsec-monitor/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ipsec_monitor $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,ipsec-monitor))
