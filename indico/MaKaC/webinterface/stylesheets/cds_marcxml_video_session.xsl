<?xml version='1.0'?>
<!--
    This file is part of Indico.
    Copyright (C) 2002 - 2015 European Organization for Nuclear Research (CERN).

    Indico is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 3 of the
    License, or (at your option) any later version.

    Indico is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Indico; if not, see <http://www.gnu.org/licenses/>.
-->

<xsl:stylesheet version='1.0' xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">

<xsl:output method="xml" version="1.0" encoding="UTF-8" indent="yes"/>

<!-- Event -->
<xsl:template match="event">

<record xsi:schemaLocation="http://www.loc.gov/MARC21/slim http://www.loc.gov/standards/marcxml/schema/MARC21slim.xsd">
<datafield tag="041" ind1=" " ind2=" ">
  <xsl:choose>
    <xsl:when test="./session/languages != ''">
      <xsl:for-each select="./session/languages/code">
        <subfield code="a"><xsl:value-of select="." /></subfield>
      </xsl:for-each>
    </xsl:when>
    <xsl:otherwise>
      <subfield code="a">eng</subfield>
    </xsl:otherwise>
  </xsl:choose>
</datafield>
<datafield tag="110" ind1=" " ind2=" ">
  <subfield code="a">CERN. Geneva</subfield>
</datafield>
<datafield tag="111" ind1=" " ind2=" ">
  <xsl:if test="./title!=''">
  <subfield code="a"><xsl:value-of select="./title"/></subfield>
  </xsl:if>
  <subfield code="c"><xsl:value-of select="./location/name" disable-output-escaping="yes"/> - <xsl:value-of select="./location/room" disable-output-escaping="yes"/></subfield>
  <subfield code="9"><xsl:value-of select="./session/startDate" disable-output-escaping="yes"/></subfield>
  <subfield code="z"><xsl:value-of select="./session/endDate" disable-output-escaping="yes"/></subfield>
  <subfield code="g"><xsl:value-of select="./ID" disable-output-escaping="yes"/></subfield>
</datafield>
<xsl:if test="./session/title!=''">
<datafield tag="245" ind1=" " ind2=" ">
  <subfield code="a"><xsl:value-of select="./session/title"/></subfield>
</datafield>
</xsl:if>
<datafield tag="260" ind1=" " ind2=" ">
  <subfield code="c"><xsl:value-of select="substring(./session/startDate,0,5)" disable-output-escaping="yes"/></subfield>
</datafield>
<datafield tag="269" ind1=" " ind2=" ">
  <subfield code="c"><xsl:value-of select="substring(./session/startDate,0,11)" disable-output-escaping="yes"/></subfield>
</datafield>
<datafield tag="300" ind1=" " ind2=" ">
  <subfield code="a">Streaming video</subfield>
  <subfield code="b"><xsl:value-of select="./session/videoFormat" /></subfield>
</datafield>
<datafield tag="340" ind1=" " ind2=" ">
  <subfield code="a">Streaming video</subfield>
</datafield>
<datafield tag="490" ind1=" " ind2=" ">
  <subfield code="a"><xsl:value-of select="./category"/></subfield>
</datafield>
<datafield tag="490" ind1=" " ind2=" ">
  <subfield code="a"><xsl:value-of select="./title" /></subfield>
</datafield>
<xsl:if test="./session/allowedAccessGroups != '' and count(./session/allowedAccessGroups) != 0">
<datafield tag="506" ind1="1" ind2=" ">
    <subfield code="a">Restricted</subfield>
    <xsl:for-each select="./session/allowedAccessGroups/group">
    <subfield code="d"><xsl:value-of select="." /></subfield>
    </xsl:for-each>
    <subfield code="f">group</subfield>
    <subfield code="2">CDS Invenio</subfield>
    <subfield code="5">SzGeCERN</subfield>
</datafield>
</xsl:if>
<xsl:if test="./session/allowedAccessEmails != '' and count(./session/allowedAccessEmails) != 0">
<datafield tag="506" ind1="1" ind2=" ">
    <subfield code="a">Restricted</subfield>
    <xsl:for-each select="./session/allowedAccessEmails/email">
    <subfield code="d"><xsl:value-of select="." /></subfield>
    </xsl:for-each>
    <subfield code="f">email</subfield>
    <subfield code="2">CDS Invenio</subfield>
    <subfield code="5">SzGeCERN</subfield>
</datafield>
</xsl:if>
<datafield tag="518" ind1=" " ind2=" ">
  <subfield code="d"><xsl:value-of select="./session/startDate" disable-output-escaping="yes"/></subfield>
</datafield>
<xsl:if test="./session/abstract!=''">
<datafield tag="520" ind1=" " ind2=" ">
  <subfield code="a">&lt;!--HTML--&gt;<xsl:value-of select="./session/abstract"/></subfield>
</datafield>
</xsl:if>
<datafield tag="650" ind1="1" ind2="7">
  <subfield code="a"><xsl:value-of select="./category"/></subfield>
</datafield>
<datafield tag="650" ind1="2" ind2="7">
  <subfield code="a">Event</subfield>
</datafield>
<datafield tag="690" ind1="C" ind2=" ">
  <subfield code="a">TALK</subfield>
</datafield>
<datafield tag="690" ind1="C" ind2=" ">
  <subfield code="a">CERN</subfield>
</datafield>
<xsl:if test="count(./session/CDSExperiment) != 0">
<datafield tag="693" ind1=" " ind2=" ">
  <subfield code="e"><xsl:value-of select="./session/CDSExperiment" disable-output-escaping="yes"/></subfield>
</datafield>
</xsl:if>
<xsl:if test="count(./session/speakers) != 0">
<xsl:for-each select="./session/speakers/user">
<datafield tag="700" ind1=" " ind2=" ">
  <subfield code="a"><xsl:apply-templates select="./name"/></subfield>
  <subfield code="e">speaker</subfield>
  <xsl:if test="./organization != ''">
  <subfield code="u"><xsl:value-of select="./organization"/></subfield>
  </xsl:if>
</datafield>
</xsl:for-each>
</xsl:if>
<datafield tag="856" ind1="4" ind2=" ">
  <subfield code="u">http://indico.cern.ch/sessionDisplay.py?confId=<xsl:value-of select="./ID" disable-output-escaping="yes"/>&amp;sessionId=<xsl:value-of select="./session/ID" disable-output-escaping="yes"/></subfield>
  <subfield code="y">Talk details</subfield>
</datafield>
<datafield tag="856" ind1="4" ind2=" ">
  <subfield code="u">http://indico.cern.ch/conferenceDisplay.py?confId=<xsl:value-of select="./ID" disable-output-escaping="yes"/></subfield>
  <subfield code="y">Event details</subfield>
</datafield>
<datafield tag="859" ind1=" " ind2=" ">
  <subfield code="f"><xsl:apply-templates select="./announcer/user/email"/></subfield>
</datafield>
<xsl:if test="count(./chair) != 0">
  <xsl:for-each select="./chair/user">
<datafield tag="906" ind1=" " ind2=" ">
  <subfield code="p"><xsl:apply-templates select="./name"/></subfield>
  <xsl:if test="./organization != ''">
  <subfield code="u"><xsl:value-of select="./organization"/></subfield>
  </xsl:if>
</datafield>
  </xsl:for-each>
</xsl:if>
<datafield tag="961" ind1=" " ind2=" ">
  <subfield code="x"><xsl:value-of select="./creationDate" disable-output-escaping="yes"/></subfield>
  <subfield code="c"><xsl:value-of select="./modificationDate" disable-output-escaping="yes"/></subfield>
</datafield>
<datafield tag="963" ind1=" " ind2=" ">
  <subfield code="a">PUBLIC</subfield>
</datafield>
<datafield tag="970" ind1=" " ind2=" ">
  <subfield code="a">INDICO.<xsl:value-of select="./ID" disable-output-escaping="yes"/>s<xsl:value-of select="./session/ID" disable-output-escaping="yes"/></subfield>
</datafield>
<datafield tag="980" ind1=" " ind2=" ">
  <subfield code="a">Indico</subfield>
</datafield>
<xsl:if test="count(./session/CDSCategories) != 0">
<datafield tag="980" ind1=" " ind2=" ">
<xsl:for-each select="./session/CDSCategories/category">
  <subfield code="a"><xsl:value-of select="." disable-output-escaping="yes"/></subfield>
</xsl:for-each>
</datafield>
</xsl:if>
<datafield tag="980" ind1=" " ind2=" ">
  <subfield code="b">TALK</subfield>
</datafield>

</record>

</xsl:template>

<xsl:template match="name">
  <xsl:value-of select="./@last" disable-output-escaping="yes"/>
  <xsl:if test="./@first!='' and ./@last!=''">
  <xsl:text disable-output-escaping="yes">, </xsl:text>
  </xsl:if>
  <xsl:value-of select="./@first" disable-output-escaping="yes"/>
</xsl:template>

</xsl:stylesheet>


