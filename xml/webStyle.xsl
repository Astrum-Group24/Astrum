<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

    <xsl: template match="/hostnames">

        <xsl:for-each select="hostname">

            <xsl:value-of select="name" />

        </xsl:for-each>

    </xsl:template>

</xsl:stylesheet>