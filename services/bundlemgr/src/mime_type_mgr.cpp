/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mime_type_mgr.h"

#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
std::shared_mutex MimeTypeMgr::mapMutex_;
std::multimap<std::string, std::string> MimeTypeMgr::mimeTypeMap_;

MimeTypeMgr::MimeTypeMgr()
{
}

MimeTypeMgr::~MimeTypeMgr()
{
}

bool MimeTypeMgr::GetMimeTypeByUri(const std::string &uri, std::vector<std::string> &mimeTypes)
{
    if (mimeTypeMap_.empty()) {
        InitMimeMap();
    }
    auto suffixIndex = uri.rfind('.');
    if (suffixIndex == std::string::npos) {
        APP_LOGE("Get suffix failed, uri is %{public}s", uri.c_str());
        return false;
    }
    std::string suffix = uri.substr(suffixIndex + 1);
    std::shared_lock<std::shared_mutex> lock(mapMutex_);
    auto range = mimeTypeMap_.equal_range(suffix);
    for (auto it = range.first; it != range.second; ++it) {
        mimeTypes.push_back(it->second);
    }
    if (mimeTypes.empty()) {
        APP_LOGE("Suffix %{public}s has no corresponding type", suffix.c_str());
        return false;
    }
    return true;
}

void MimeTypeMgr::InitMimeMap()
{
    std::unique_lock<std::shared_mutex> lock(mapMutex_);
    mimeTypeMap_.emplace("323", "text/h323");
    mimeTypeMap_.emplace("3g2", "video/3gpp2");
    mimeTypeMap_.emplace("3gp", "video/3gpp");
    mimeTypeMap_.emplace("3gpp", "audio/3gpp");
    mimeTypeMap_.emplace("3gpp", "video/3gpp");
    mimeTypeMap_.emplace("3gpp2", "video/3gpp2");
    mimeTypeMap_.emplace("VOB", "video/mpeg");
    mimeTypeMap_.emplace("aac", "audio/aac");
    mimeTypeMap_.emplace("aac", "audio/aac-adts");
    mimeTypeMap_.emplace("abw", "application/x-abiword");
    mimeTypeMap_.emplace("aif", "audio/x-aiff");
    mimeTypeMap_.emplace("aifc", "audio/x-aiff");
    mimeTypeMap_.emplace("aiff", "audio/x-aiff");
    mimeTypeMap_.emplace("amr", "audio/amr");
    mimeTypeMap_.emplace("asc", "text/plain");
    mimeTypeMap_.emplace("asf", "video/x-ms-asf");
    mimeTypeMap_.emplace("asx", "video/x-ms-asf");
    mimeTypeMap_.emplace("avi", "video/avi");
    mimeTypeMap_.emplace("awb", "audio/amr-wb");
    mimeTypeMap_.emplace("bcpio", "application/x-bcpio");
    mimeTypeMap_.emplace("bib", "text/x-bibtex");
    mimeTypeMap_.emplace("bmp", "image/bmp");
    mimeTypeMap_.emplace("bmp", "image/x-ms-bmp");
    mimeTypeMap_.emplace("boo", "text/x-boo");
    mimeTypeMap_.emplace("book", "application/x-maker");
    mimeTypeMap_.emplace("c", "text/x-csrc");
    mimeTypeMap_.emplace("c++", "text/x-c++src");
    mimeTypeMap_.emplace("cc", "text/x-c++src");
    mimeTypeMap_.emplace("cdf", "application/x-cdf");
    mimeTypeMap_.emplace("cdr", "image/x-coreldraw");
    mimeTypeMap_.emplace("cdt", "image/x-coreldrawtemplate");
    mimeTypeMap_.emplace("cdy", "application/vnd.cinderella");
    mimeTypeMap_.emplace("cer", "application/pkix-cert");
    mimeTypeMap_.emplace("chrt", "application/x-kchart");
    mimeTypeMap_.emplace("cls", "text/x-tex");
    mimeTypeMap_.emplace("cod", "application/vnd.rim.cod");
    mimeTypeMap_.emplace("cpio", "application/x-cpio");
    mimeTypeMap_.emplace("cpp", "text/x-c++src");
    mimeTypeMap_.emplace("cpt", "image/x-corelphotopaint");
    mimeTypeMap_.emplace("crl", "application/x-pkcs7-crl");
    mimeTypeMap_.emplace("crt", "application/x-x509-ca-cert");
    mimeTypeMap_.emplace("crt", "application/x-x509-server-cert");
    mimeTypeMap_.emplace("crt", "application/x-x509-user-cert");
    mimeTypeMap_.emplace("csh", "text/x-csh");
    mimeTypeMap_.emplace("css", "text/css");
    mimeTypeMap_.emplace("csv", "text/comma-separated-values");
    mimeTypeMap_.emplace("cur", "image/ico");
    mimeTypeMap_.emplace("cxx", "text/x-c++src");
    mimeTypeMap_.emplace("d", "text/x-dsrc");
    mimeTypeMap_.emplace("dcr", "application/x-director");
    mimeTypeMap_.emplace("deb", "application/x-debian-package");
    mimeTypeMap_.emplace("dif", "video/dv");
    mimeTypeMap_.emplace("diff", "text/plain");
    mimeTypeMap_.emplace("dir", "application/x-director");
    mimeTypeMap_.emplace("djv", "image/vnd.djvu");
    mimeTypeMap_.emplace("djvu", "image/vnd.djvu");
    mimeTypeMap_.emplace("dl", "video/dl");
    mimeTypeMap_.emplace("dmg", "application/x-apple-diskimage");
    mimeTypeMap_.emplace("dms", "application/x-dms");
    mimeTypeMap_.emplace("doc", "application/msword");
    mimeTypeMap_.emplace("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
    mimeTypeMap_.emplace("dot", "application/msword");
    mimeTypeMap_.emplace("dotx", "application/vnd.openxmlformats-officedocument.wordprocessingml.template");
    mimeTypeMap_.emplace("dv", "video/dv");
    mimeTypeMap_.emplace("dvi", "application/x-dvi");
    mimeTypeMap_.emplace("dxr", "application/x-director");
    mimeTypeMap_.emplace("etx", "text/x-setext");
    mimeTypeMap_.emplace("ez", "application/andrew-inset");
    mimeTypeMap_.emplace("fb", "application/x-maker");
    mimeTypeMap_.emplace("fbdoc", "application/x-maker");
    mimeTypeMap_.emplace("fig", "application/x-xfig");
    mimeTypeMap_.emplace("flac", "application/x-flac");
    mimeTypeMap_.emplace("flac", "audio/flac");
    mimeTypeMap_.emplace("fli", "video/fli");
    mimeTypeMap_.emplace("frame", "application/x-maker");
    mimeTypeMap_.emplace("frm", "application/x-maker");
    mimeTypeMap_.emplace("gcd", "text/x-pcs-gcd");
    mimeTypeMap_.emplace("gcf", "application/x-graphing-calculator");
    mimeTypeMap_.emplace("gif", "image/gif");
    mimeTypeMap_.emplace("gnumeric", "application/x-gnumeric");
    mimeTypeMap_.emplace("gsf", "application/x-font");
    mimeTypeMap_.emplace("gsm", "audio/x-gsm");
    mimeTypeMap_.emplace("gtar", "application/x-gtar");
    mimeTypeMap_.emplace("h", "text/x-chdr");
    mimeTypeMap_.emplace("h++", "text/x-c++hdr");
    mimeTypeMap_.emplace("hdf", "application/x-hdf");
    mimeTypeMap_.emplace("hh", "text/x-c++hdr");
    mimeTypeMap_.emplace("hpp", "text/x-c++hdr");
    mimeTypeMap_.emplace("hqx", "application/mac-binhex40");
    mimeTypeMap_.emplace("hs", "text/x-haskell");
    mimeTypeMap_.emplace("hta", "application/hta");
    mimeTypeMap_.emplace("htc", "text/x-component");
    mimeTypeMap_.emplace("htm", "text/html");
    mimeTypeMap_.emplace("html", "text/html");
    mimeTypeMap_.emplace("hxx", "text/x-c++hdr");
    mimeTypeMap_.emplace("ica", "application/x-ica");
    mimeTypeMap_.emplace("ice", "x-conference/x-cooltalk");
    mimeTypeMap_.emplace("ico", "image/ico");
    mimeTypeMap_.emplace("ico", "image/x-icon");
    mimeTypeMap_.emplace("ics", "text/calendar");
    mimeTypeMap_.emplace("icz", "text/calendar");
    mimeTypeMap_.emplace("ief", "image/ief");
    mimeTypeMap_.emplace("iges", "model/iges");
    mimeTypeMap_.emplace("igs", "model/iges");
    mimeTypeMap_.emplace("iii", "application/x-iphone");
    mimeTypeMap_.emplace("imy", "audio/imelody");
    mimeTypeMap_.emplace("ins", "application/x-internet-signup");
    mimeTypeMap_.emplace("iso", "application/x-iso9660-image");
    mimeTypeMap_.emplace("isp", "application/x-internet-signup");
    mimeTypeMap_.emplace("java", "text/x-java");
    mimeTypeMap_.emplace("jmz", "application/x-jmol");
    mimeTypeMap_.emplace("jng", "image/x-jng");
    mimeTypeMap_.emplace("jpe", "image/jpeg");
    mimeTypeMap_.emplace("jpeg", "image/jpeg");
    mimeTypeMap_.emplace("jpg", "image/jpeg");
    mimeTypeMap_.emplace("kar", "audio/midi");
    mimeTypeMap_.emplace("key", "application/pgp-keys");
    mimeTypeMap_.emplace("kil", "application/x-killustrator");
    mimeTypeMap_.emplace("kpr", "application/x-kpresenter");
    mimeTypeMap_.emplace("kpt", "application/x-kpresenter");
    mimeTypeMap_.emplace("ksp", "application/x-kspread");
    mimeTypeMap_.emplace("kwd", "application/x-kword");
    mimeTypeMap_.emplace("kwt", "application/x-kword");
    mimeTypeMap_.emplace("latex", "application/x-latex");
    mimeTypeMap_.emplace("lha", "application/x-lha");
    mimeTypeMap_.emplace("lhs", "text/x-literate-haskell");
    mimeTypeMap_.emplace("lsf", "video/x-la-asf");
    mimeTypeMap_.emplace("lsx", "video/x-la-asf");
    mimeTypeMap_.emplace("ltx", "text/x-tex");
    mimeTypeMap_.emplace("lzh", "application/x-lzh");
    mimeTypeMap_.emplace("lzx", "application/x-lzx");
    mimeTypeMap_.emplace("m3u", "audio/mpegurl");
    mimeTypeMap_.emplace("m3u", "audio/x-mpegurl");
    mimeTypeMap_.emplace("m4a", "audio/mpeg");
    mimeTypeMap_.emplace("m4v", "video/m4v");
    mimeTypeMap_.emplace("maker", "application/x-maker");
    mimeTypeMap_.emplace("man", "application/x-troff-man");
    mimeTypeMap_.emplace("mdb", "application/msaccess");
    mimeTypeMap_.emplace("mesh", "model/mesh");
    mimeTypeMap_.emplace("mid", "audio/midi");
    mimeTypeMap_.emplace("midi", "audio/midi");
    mimeTypeMap_.emplace("mif", "application/x-mif");
    mimeTypeMap_.emplace("mka", "audio/x-matroska");
    mimeTypeMap_.emplace("mkv", "video/x-matroska");
    mimeTypeMap_.emplace("mm", "application/x-freemind");
    mimeTypeMap_.emplace("mmf", "application/vnd.smaf");
    mimeTypeMap_.emplace("mml", "text/mathml");
    mimeTypeMap_.emplace("mng", "video/x-mng");
    mimeTypeMap_.emplace("moc", "text/x-moc");
    mimeTypeMap_.emplace("mov", "video/quicktime");
    mimeTypeMap_.emplace("movie", "video/x-sgi-movie");
    mimeTypeMap_.emplace("mp2", "audio/mpeg");
    mimeTypeMap_.emplace("mp3", "audio/mpeg");
    mimeTypeMap_.emplace("mp4", "video/mp4");
    mimeTypeMap_.emplace("mpe", "video/mpeg");
    mimeTypeMap_.emplace("mpeg", "video/mpeg");
    mimeTypeMap_.emplace("mpega", "audio/mpeg");
    mimeTypeMap_.emplace("mpg", "video/mpeg");
    mimeTypeMap_.emplace("mpga", "audio/mpeg");
    mimeTypeMap_.emplace("msh", "model/mesh");
    mimeTypeMap_.emplace("msi", "application/x-msi");
    mimeTypeMap_.emplace("mxmf", "audio/mobile-xmf");
    mimeTypeMap_.emplace("mxu", "video/vnd.mpegurl");
    mimeTypeMap_.emplace("nb", "application/mathematica");
    mimeTypeMap_.emplace("nwc", "application/x-nwc");
    mimeTypeMap_.emplace("o", "application/x-object");
    mimeTypeMap_.emplace("oda", "application/oda");
    mimeTypeMap_.emplace("odb", "application/vnd.oasis.opendocument.database");
    mimeTypeMap_.emplace("odf", "application/vnd.oasis.opendocument.formula");
    mimeTypeMap_.emplace("odg", "application/vnd.oasis.opendocument.graphics");
    mimeTypeMap_.emplace("odi", "application/vnd.oasis.opendocument.image");
    mimeTypeMap_.emplace("ods", "application/vnd.oasis.opendocument.spreadsheet");
    mimeTypeMap_.emplace("odt", "application/vnd.oasis.opendocument.text");
    mimeTypeMap_.emplace("oga", "application/ogg");
    mimeTypeMap_.emplace("ogg", "application/ogg");
    mimeTypeMap_.emplace("ota", "audio/midi");
    mimeTypeMap_.emplace("otg", "application/vnd.oasis.opendocument.graphics-template");
    mimeTypeMap_.emplace("oth", "application/vnd.oasis.opendocument.text-web");
    mimeTypeMap_.emplace("ots", "application/vnd.oasis.opendocument.spreadsheet-template");
    mimeTypeMap_.emplace("ott", "application/vnd.oasis.opendocument.text-template");
    mimeTypeMap_.emplace("oza", "application/x-oz-application");
    mimeTypeMap_.emplace("p", "text/x-pascal");
    mimeTypeMap_.emplace("p12", "application/x-pkcs12");
    mimeTypeMap_.emplace("p7r", "application/x-pkcs7-certreqresp");
    mimeTypeMap_.emplace("pac", "application/x-ns-proxy-autoconfig");
    mimeTypeMap_.emplace("pas", "text/x-pascal");
    mimeTypeMap_.emplace("pat", "image/x-coreldrawpattern");
    mimeTypeMap_.emplace("pbm", "image/x-portable-bitmap");
    mimeTypeMap_.emplace("pcf", "application/x-font");
    mimeTypeMap_.emplace("pcf.Z", "application/x-font");
    mimeTypeMap_.emplace("pcx", "image/pcx");
    mimeTypeMap_.emplace("pdf", "application/pdf");
    mimeTypeMap_.emplace("pem", "application/x-pem-file");
    mimeTypeMap_.emplace("pfa", "application/x-font");
    mimeTypeMap_.emplace("pfb", "application/x-font");
    mimeTypeMap_.emplace("pfx", "application/x-pkcs12");
    mimeTypeMap_.emplace("pgm", "image/x-portable-graymap");
    mimeTypeMap_.emplace("pgn", "application/x-chess-pgn");
    mimeTypeMap_.emplace("pgp", "application/pgp-signature");
    mimeTypeMap_.emplace("phps", "text/text");
    mimeTypeMap_.emplace("pls", "audio/x-scpls");
    mimeTypeMap_.emplace("png", "image/png");
    mimeTypeMap_.emplace("pnm", "image/x-portable-anymap");
    mimeTypeMap_.emplace("po", "text/plain");
    mimeTypeMap_.emplace("pot", "application/vnd.ms-powerpoint");
    mimeTypeMap_.emplace("potx", "application/vnd.openxmlformats-officedocument.presentationml.template");
    mimeTypeMap_.emplace("ppm", "image/x-portable-pixmap");
    mimeTypeMap_.emplace("pps", "application/vnd.ms-powerpoint");
    mimeTypeMap_.emplace("ppsx", "application/vnd.openxmlformats-officedocument.presentationml.slideshow");
    mimeTypeMap_.emplace("ppt", "application/vnd.ms-powerpoint");
    mimeTypeMap_.emplace("pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation");
    mimeTypeMap_.emplace("prf", "application/pics-rules");
    mimeTypeMap_.emplace("psd", "image/x-photoshop");
    mimeTypeMap_.emplace("qt", "video/quicktime");
    mimeTypeMap_.emplace("qtl", "application/x-quicktimeplayer");
    mimeTypeMap_.emplace("ra", "audio/x-pn-realaudio");
    mimeTypeMap_.emplace("ra", "audio/x-realaudio");
    mimeTypeMap_.emplace("ram", "audio/x-pn-realaudio");
    mimeTypeMap_.emplace("rar", "application/rar");
    mimeTypeMap_.emplace("ras", "image/x-cmu-raster");
    mimeTypeMap_.emplace("rdf", "application/rdf+xml");
    mimeTypeMap_.emplace("rgb", "image/x-rgb");
    mimeTypeMap_.emplace("rm", "audio/x-pn-realaudio");
    mimeTypeMap_.emplace("roff", "application/x-troff");
    mimeTypeMap_.emplace("rss", "application/rss+xml");
    mimeTypeMap_.emplace("rtf", "text/rtf");
    mimeTypeMap_.emplace("rtttl", "audio/midi");
    mimeTypeMap_.emplace("rtx", "text/richtext");
    mimeTypeMap_.emplace("sd2", "audio/x-sd2");
    mimeTypeMap_.emplace("sda", "application/vnd.stardivision.draw");
    mimeTypeMap_.emplace("sdc", "application/vnd.stardivision.calc");
    mimeTypeMap_.emplace("sdd", "application/vnd.stardivision.impress");
    mimeTypeMap_.emplace("sdp", "application/vnd.stardivision.impress");
    mimeTypeMap_.emplace("sdw", "application/vnd.stardivision.writer");
    mimeTypeMap_.emplace("sgf", "application/x-go-sgf");
    mimeTypeMap_.emplace("sgl", "application/vnd.stardivision.writer-global");
    mimeTypeMap_.emplace("shar", "application/x-shar");
    mimeTypeMap_.emplace("sid", "audio/prs.sid");
    mimeTypeMap_.emplace("silo", "model/mesh");
    mimeTypeMap_.emplace("sisx", "x-epoc/x-sisx-app");
    mimeTypeMap_.emplace("sit", "application/x-stuffit");
    mimeTypeMap_.emplace("skd", "application/x-koan");
    mimeTypeMap_.emplace("skm", "application/x-koan");
    mimeTypeMap_.emplace("skp", "application/x-koan");
    mimeTypeMap_.emplace("skt", "application/x-koan");
    mimeTypeMap_.emplace("smf", "application/vnd.stardivision.math");
    mimeTypeMap_.emplace("snd", "audio/basic");
    mimeTypeMap_.emplace("spl", "application/futuresplash");
    mimeTypeMap_.emplace("spl", "application/x-futuresplash");
    mimeTypeMap_.emplace("src", "application/x-wais-source");
    mimeTypeMap_.emplace("stc", "application/vnd.sun.xml.calc.template");
    mimeTypeMap_.emplace("std", "application/vnd.sun.xml.draw.template");
    mimeTypeMap_.emplace("sti", "application/vnd.sun.xml.impress.template");
    mimeTypeMap_.emplace("stl", "application/vnd.ms-pki.stl");
    mimeTypeMap_.emplace("stw", "application/vnd.sun.xml.writer.template");
    mimeTypeMap_.emplace("sty", "text/x-tex");
    mimeTypeMap_.emplace("sv4cpio", "application/x-sv4cpio");
    mimeTypeMap_.emplace("sv4crc", "application/x-sv4crc");
    mimeTypeMap_.emplace("svg", "image/svg+xml");
    mimeTypeMap_.emplace("svgz", "image/svg+xml");
    mimeTypeMap_.emplace("swf", "application/x-shockwave-flash");
    mimeTypeMap_.emplace("sxc", "application/vnd.sun.xml.calc");
    mimeTypeMap_.emplace("sxd", "application/vnd.sun.xml.draw");
    mimeTypeMap_.emplace("sxg", "application/vnd.sun.xml.writer.global");
    mimeTypeMap_.emplace("sxi", "application/vnd.sun.xml.impress");
    mimeTypeMap_.emplace("sxm", "application/vnd.sun.xml.math");
    mimeTypeMap_.emplace("sxw", "application/vnd.sun.xml.writer");
    mimeTypeMap_.emplace("t", "application/x-troff");
    mimeTypeMap_.emplace("tar", "application/x-tar");
    mimeTypeMap_.emplace("taz", "application/x-gtar");
    mimeTypeMap_.emplace("tcl", "text/x-tcl");
    mimeTypeMap_.emplace("tex", "text/x-tex");
    mimeTypeMap_.emplace("texi", "application/x-texinfo");
    mimeTypeMap_.emplace("texinfo", "application/x-texinfo");
    mimeTypeMap_.emplace("text", "text/plain");
    mimeTypeMap_.emplace("tgz", "application/x-gtar");
    mimeTypeMap_.emplace("tif", "image/tiff");
    mimeTypeMap_.emplace("tiff", "image/tiff");
    mimeTypeMap_.emplace("torrent", "application/x-bittorrent");
    mimeTypeMap_.emplace("ts", "video/mp2ts");
    mimeTypeMap_.emplace("tsp", "application/dsptype");
    mimeTypeMap_.emplace("tsv", "text/tab-separated-values");
    mimeTypeMap_.emplace("txt", "text/plain");
    mimeTypeMap_.emplace("udeb", "application/x-debian-package");
    mimeTypeMap_.emplace("uls", "text/iuls");
    mimeTypeMap_.emplace("ustar", "application/x-ustar");
    mimeTypeMap_.emplace("vcd", "application/x-cdlink");
    mimeTypeMap_.emplace("vcf", "text/x-vcard");
    mimeTypeMap_.emplace("vcs", "text/x-vcalendar");
    mimeTypeMap_.emplace("vor", "application/vnd.stardivision.writer");
    mimeTypeMap_.emplace("vsd", "application/vnd.visio");
    mimeTypeMap_.emplace("wad", "application/x-doom");
    mimeTypeMap_.emplace("wav", "audio/x-wav");
    mimeTypeMap_.emplace("wax", "audio/x-ms-wax");
    mimeTypeMap_.emplace("wbmp", "image/vnd.wap.wbmp");
    mimeTypeMap_.emplace("webarchive", "application/x-webarchive");
    mimeTypeMap_.emplace("webarchivexml", "application/x-webarchive-xml");
    mimeTypeMap_.emplace("webm", "video/webm");
    mimeTypeMap_.emplace("webp", "image/webp");
    mimeTypeMap_.emplace("wm", "video/x-ms-wm");
    mimeTypeMap_.emplace("wma", "audio/x-ms-wma");
    mimeTypeMap_.emplace("wmd", "application/x-ms-wmd");
    mimeTypeMap_.emplace("wmv", "video/x-ms-wmv");
    mimeTypeMap_.emplace("wmx", "video/x-ms-wmx");
    mimeTypeMap_.emplace("wmz", "application/x-ms-wmz");
    mimeTypeMap_.emplace("wrf", "video/x-webex");
    mimeTypeMap_.emplace("wvx", "video/x-ms-wvx");
    mimeTypeMap_.emplace("wz", "application/x-wingz");
    mimeTypeMap_.emplace("xbm", "image/x-xbitmap");
    mimeTypeMap_.emplace("xcf", "application/x-xcf");
    mimeTypeMap_.emplace("xhtml", "application/xhtml+xml");
    mimeTypeMap_.emplace("xls", "application/vnd.ms-excel");
    mimeTypeMap_.emplace("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    mimeTypeMap_.emplace("xlt", "application/vnd.ms-excel");
    mimeTypeMap_.emplace("xltx", "application/vnd.openxmlformats-officedocument.spreadsheetml.template");
    mimeTypeMap_.emplace("xmf", "audio/midi");
    mimeTypeMap_.emplace("xml", "text/xml");
    mimeTypeMap_.emplace("xpm", "image/x-xpixmap");
    mimeTypeMap_.emplace("xwd", "image/x-xwindowdump");
    mimeTypeMap_.emplace("zip", "application/zip");
}
}
}