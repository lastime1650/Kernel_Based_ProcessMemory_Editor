// Offline PDB inspection using DIA. Never opens or attaches to a process.
#include <windows.h>
#include <dia2.h>
#include <cvconst.h>
#include <string>
#include <vector>
#include <set>
#include <sstream>
#include <iostream>
#include <iomanip>

template<class T> struct Ref {
    T* p=nullptr;
    ~Ref(){if(p)p->Release();}
    T** out(){if(p)p->Release();p=nullptr;return &p;}
    T* operator->()const{return p;}
};
std::string utf8(const std::wstring& s){
    if(s.empty())return {};
    int n=WideCharToMultiByte(CP_UTF8,0,s.data(),static_cast<int>(s.size()),nullptr,0,nullptr,nullptr);
    std::string r(n,'\0');WideCharToMultiByte(CP_UTF8,0,s.data(),static_cast<int>(s.size()),r.data(),n,nullptr,nullptr);return r;
}
std::string quoted(const std::string& s){
    std::ostringstream o;o<<'"';
    for(unsigned char c:s){if(c=='"'||c=='\\')o<<'\\'<<c;else if(c<32)o<<"\\u"<<std::hex<<std::setw(4)<<std::setfill('0')<<int(c)<<std::dec;else o<<c;}
    o<<'"';return o.str();
}
std::wstring symbolName(IDiaSymbol* s){BSTR b=nullptr;std::wstring result;if(s->get_name(&b)==S_OK&&b)result.assign(b,SysStringLen(b));if(b)SysFreeString(b);return result;}
struct Type{std::wstring name=L"unknown";std::string kind="unknown";ULONGLONG length=0;};
Type typeOf(IDiaSymbol* s,int depth=0){
    Type t;if(!s||depth>8)return t;
    DWORD tag=0;s->get_symTag(&tag);s->get_length(&t.length);
    if(tag==SymTagPointerType){Ref<IDiaSymbol> child;s->get_type(child.out());t.name=typeOf(child.p,depth+1).name+L"*";t.kind="pointer";return t;}
    if(tag==SymTagTypedef){Ref<IDiaSymbol> child;s->get_type(child.out());auto base=typeOf(child.p,depth+1);t.name=symbolName(s);t.kind=base.kind;t.length=base.length;return t;}
    if(tag==SymTagBaseType){DWORD base=0;s->get_baseType(&base);
        if(base==btVoid){t.name=L"void";t.kind="void";}
        else if(base==btFloat){t.name=t.length==4?L"float":L"double";t.kind="float";}
        else if(base==btChar||base==btWChar){t.name=base==btChar?L"char":L"wchar_t";t.kind="integer";}
        else if(base==btBool){t.name=L"bool";t.kind="integer";}
        else if(base==btInt||base==btUInt||base==btLong||base==btULong){t.name=(base==btUInt||base==btULong?L"uint":L"int")+std::to_wstring(t.length*8)+L"_t";t.kind="integer";}
        return t;
    }
    t.name=symbolName(s);if(t.name.empty())t.name=L"unknown";
    if(tag==SymTagEnum)t.kind="integer";else if(tag==SymTagUDT)t.kind="aggregate";else if(tag==SymTagArrayType)t.kind="array";
    return t;
}
std::string typeJson(const Type& t){return "{\"type\":"+quoted(utf8(t.name))+",\"kind\":"+quoted(t.kind)+",\"size\":"+std::to_string(t.length)+"}";}
std::string safeName(const std::wstring& value){
    std::string name=utf8(value);for(char& c:name)if(!(isalnum(static_cast<unsigned char>(c))||c=='_'||c==':'||c=='$'||c=='<'||c=='>'||c==' '))c='_';
    if(name.empty()||!(isalpha(static_cast<unsigned char>(name[0]))||name[0]=='_'))name="t_"+name;
    return name.substr(0,120);
}
std::string layoutType(IDiaSymbol* symbol,int depth=0){
    if(!symbol||depth>8)return "\"type\":\"bytes\",\"length\":1,\"readonly\":true";
    DWORD tag=0;ULONGLONG length=0;symbol->get_symTag(&tag);symbol->get_length(&length);
    Ref<IDiaSymbol> child;
    if(tag==SymTagTypedef){symbol->get_type(child.out());return layoutType(child.p,depth+1);}
    if(tag==SymTagPointerType){
        symbol->get_type(child.out());DWORD childTag=0;if(child.p)child->get_symTag(&childTag);
        return "\"type\":\"pointer\""+(childTag==SymTagUDT?",\"ref\":"+quoted(safeName(symbolName(child.p))):"");
    }
    if(tag==SymTagUDT)return "\"type\":\"struct\",\"ref\":"+quoted(safeName(symbolName(symbol)));
    if(tag==SymTagArrayType){
        DWORD count=0;symbol->get_count(&count);symbol->get_type(child.out());DWORD childTag=0;if(child.p)child->get_symTag(&childTag);
        if(count&&count<=256&&childTag!=SymTagArrayType)return layoutType(child.p,depth+1)+",\"count\":"+std::to_string(count);
    }
    if(tag==SymTagEnum){symbol->get_type(child.out());if(child.p)return layoutType(child.p,depth+1);}
    if(tag==SymTagBaseType){
        DWORD base=0;symbol->get_baseType(&base);
        if(base==btFloat&&(length==4||length==8))return "\"type\":\"float"+std::to_string(length*8)+"\"";
        if((base==btChar||base==btWChar||base==btBool||base==btInt||base==btUInt||base==btLong||base==btULong)&&(length==1||length==2||length==4||length==8))
            return "\"type\":\""+std::string(base==btUInt||base==btULong||base==btWChar||base==btBool?"uint":"int")+std::to_string(length*8)+"\"";
    }
    return "\"type\":\"bytes\",\"length\":"+std::to_string(length&&length<=4096?length:1)+",\"readonly\":true";
}
std::string structureJson(IDiaSymbol* symbol,std::vector<std::string>& unsupported){
    ULONGLONG size=0;symbol->get_length(&size);if(!size||size>1048576)return {};
    const auto name=safeName(symbolName(symbol));std::vector<std::string> fields;Ref<IDiaEnumSymbols> entries;
    if(symbol->findChildren(SymTagData,nullptr,nsNone,entries.out())==S_OK&&entries.p){
        Ref<IDiaSymbol> entry;ULONG got=0;
        while(fields.size()<128&&entries->Next(1,entry.out(),&got)==S_OK&&got){
            DWORD kind=0,loc=0;LONG offset=0;entry->get_dataKind(&kind);entry->get_locationType(&loc);
            if(kind!=DataIsMember)continue;
            if(loc==LocIsBitField||entry->get_offset(&offset)!=S_OK||offset<0){unsupported.push_back(quoted(name+"."+utf8(symbolName(entry.p))+" (bitfield / layout unavailable)"));continue;}
            Ref<IDiaSymbol> type;entry->get_type(type.out());
            fields.push_back("{\"name\":"+quoted(safeName(symbolName(entry.p)))+",\"offset\":"+std::to_string(offset)+","+layoutType(type.p)+"}");
        }
    }
    if(fields.empty())return {};
    std::string result="{\"name\":"+quoted(name)+",\"size\":"+std::to_string(size)+",\"fields\":[";
    for(size_t i=0;i<fields.size();++i){if(i)result+=',';result+=fields[i];}return result+"]}";
}
std::string functionJson(IDiaSymbol* s,DWORD rva,bool publicOnly){
    ULONGLONG length=0;s->get_length(&length);
    std::string result="{\"rva\":"+std::to_string(rva)+",\"name\":"+quoted(utf8(symbolName(s)))+",\"size\":"+std::to_string(length);
    if(publicOnly)return result+",\"types_available\":false,\"parameters\":[],\"source\":\"pdb_public\"}";
    Ref<IDiaSymbol> fnType;bool typed=s->get_type(fnType.out())==S_OK&&fnType.p;
    DWORD convention=0;if(typed)fnType->get_callingConvention(&convention);
    Ref<IDiaSymbol> object;bool member=typed&&fnType->get_objectPointerType(object.out())==S_OK&&object.p;
    Ref<IDiaSymbol> returnType;if(typed)fnType->get_type(returnType.out());
    std::vector<Type> params;Ref<IDiaEnumSymbols> args;
    if(typed&&fnType->findChildren(SymTagFunctionArgType,nullptr,nsNone,args.out())==S_OK&&args.p){
        Ref<IDiaSymbol> arg;ULONG got=0;
        while(params.size()<64&&args->Next(1,arg.out(),&got)==S_OK&&got){Ref<IDiaSymbol> argType;arg->get_type(argType.out());params.push_back(typeOf(argType.p));}
    }
    std::vector<std::wstring> names;Ref<IDiaEnumSymbols> data;
    if(s->findChildren(SymTagData,nullptr,nsNone,data.out())==S_OK&&data.p){
        Ref<IDiaSymbol> entry;ULONG got=0;
        while(names.size()<64&&data->Next(1,entry.out(),&got)==S_OK&&got){DWORD kind=0;entry->get_dataKind(&kind);if(kind==DataIsParam)names.push_back(symbolName(entry.p));}
    }
    result+=",\"source\":\"pdb_function\",\"types_available\":"+std::string(typed?"true":"false")+
        ",\"calling_convention\":"+std::to_string(convention)+",\"requires_object\":"+(member?"true":"false")+
        ",\"return\":"+typeJson(typeOf(returnType.p))+",\"parameters\":[";
    for(size_t i=0;i<params.size();++i){if(i)result+=',';auto j=typeJson(params[i]);j.pop_back();
        result+=j+",\"name\":"+quoted(utf8(i<names.size()?names[i]:L"arg"+std::to_wstring(i+1)))+"}";}
    return result+"]}";
}
int wmain(int argc,wchar_t** argv){
    if(argc!=3){std::cout<<"{\"success\":false,\"error\":\"Expected PDB path and DIA DLL path\"}";return 2;}
    HRESULT init=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
    if(FAILED(init)){std::cout<<"{\"success\":false,\"error\":\"COM initialization failed\"}";return 2;}
    HMODULE module=LoadLibraryExW(argv[2],nullptr,LOAD_WITH_ALTERED_SEARCH_PATH);
    int exit=1;
    {
        Ref<IClassFactory> factory;Ref<IDiaDataSource> source;Ref<IDiaSession> session;Ref<IDiaSymbol> global;
        using GET_CLASS=HRESULT(STDAPICALLTYPE*)(REFCLSID,REFIID,LPVOID*);
        auto getClass=module?reinterpret_cast<GET_CLASS>(GetProcAddress(module,"DllGetClassObject")):nullptr;
        HRESULT hr=getClass?getClass(CLSID_DiaSource,IID_IClassFactory,reinterpret_cast<void**>(factory.out())):E_FAIL;
        if(SUCCEEDED(hr))hr=factory->CreateInstance(nullptr,__uuidof(IDiaDataSource),reinterpret_cast<void**>(source.out()));
        if(SUCCEEDED(hr))hr=source->loadDataFromPdb(argv[1]);
        if(SUCCEEDED(hr))hr=source->openSession(session.out());
        if(SUCCEEDED(hr))hr=session->get_globalScope(global.out());
        if(FAILED(hr))std::cout<<"{\"success\":false,\"error\":\"DIA PDB load failed\",\"hresult\":"<<static_cast<unsigned long>(hr)<<"}";
        else{
            GUID guid={};DWORD age=0;global->get_guid(&guid);global->get_age(&age);
            wchar_t guidText[40];StringFromGUID2(guid,guidText,40);
            std::vector<std::string> rows;std::set<std::pair<DWORD,std::wstring>> seen;
            bool truncated=false;
            auto enumerate=[&](IDiaSymbol* parent,DWORD tag){
                Ref<IDiaEnumSymbols> entries;
                if(parent->findChildren(static_cast<enum SymTagEnum>(tag),nullptr,nsNone,entries.out())!=S_OK||!entries.p)return;
                Ref<IDiaSymbol> s;ULONG got=0;
                while(entries->Next(1,s.out(),&got)==S_OK&&got){
                    DWORD rva=0;if(s->get_relativeVirtualAddress(&rva)!=S_OK||!rva)continue;
                    if(tag==SymTagPublicSymbol){BOOL code=FALSE;s->get_code(&code);if(!code)continue;}
                    if(!seen.emplace(rva,symbolName(s.p)).second)continue;
                    if(rows.size()>=50000){truncated=true;break;}
                    rows.push_back(functionJson(s.p,rva,tag==SymTagPublicSymbol));
                }
            };
            enumerate(global.p,SymTagFunction);
            Ref<IDiaEnumSymbols> compilands;
            if(global->findChildren(SymTagCompiland,nullptr,nsNone,compilands.out())==S_OK&&compilands.p){
                Ref<IDiaSymbol> compiland;ULONG got=0;
                while(!truncated&&compilands->Next(1,compiland.out(),&got)==S_OK&&got)enumerate(compiland.p,SymTagFunction);
            }
            if(!truncated)enumerate(global.p,SymTagPublicSymbol);
            std::cout<<"{\"success\":true,\"guid\":"<<quoted(utf8(guidText))<<",\"age\":"<<age<<",\"truncated\":"<<(truncated?"true":"false")<<",\"functions\":[";
            for(size_t i=0;i<rows.size();++i){if(i)std::cout<<',';std::cout<<rows[i];}
            std::vector<std::string> layouts,unsupported;std::set<std::string> typeNames;Ref<IDiaEnumSymbols> types;
            if(global->findChildren(SymTagUDT,nullptr,nsNone,types.out())==S_OK&&types.p){
                Ref<IDiaSymbol> type;ULONG got=0;
                while(layouts.size()<64&&types->Next(1,type.out(),&got)==S_OK&&got){
                    if(!typeNames.insert(safeName(symbolName(type.p))).second)continue;
                    auto layout=structureJson(type.p,unsupported);if(!layout.empty())layouts.push_back(layout);
                }
            }
            std::cout<<"],\"structures\":[";for(size_t i=0;i<layouts.size();++i){if(i)std::cout<<',';std::cout<<layouts[i];}
            std::cout<<"],\"unsupported_types\":[";for(size_t i=0;i<unsupported.size();++i){if(i)std::cout<<',';std::cout<<unsupported[i];}
            std::cout<<"]}";exit=0;
        }
    }
    if(module)FreeLibrary(module);CoUninitialize();return exit;
}
