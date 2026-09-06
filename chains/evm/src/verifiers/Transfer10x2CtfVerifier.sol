// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Transfer10x2CtfVerifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 20491192805390485299153009773594534940189261866228447918068658471970481763042;
    uint256 constant alphay  = 9383485363053290200918347156157836566562967994039712273449902621266178545958;
    uint256 constant betax1  = 4252822878758300859123897981450591353533073413197771768651442665752259397132;
    uint256 constant betax2  = 6375614351688725206403948262868962793625744043794305715222011528459656738731;
    uint256 constant betay1  = 21847035105528745403288232691147584728191162732299865338377159692350059136679;
    uint256 constant betay2  = 10505242626370262277552901082094356697409835680220590971873171140371331206856;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant deltax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant deltay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant deltay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;

    
    uint256 constant IC0x = 18278513728467992130888497715878743009141123024776834510355742216914027763354;
    uint256 constant IC0y = 2845774954058461268115217009998317133381369353860290733713531056127519318353;
    
    uint256 constant IC1x = 12883365296165799503531502347022615579031503126578130212047713939632806768686;
    uint256 constant IC1y = 21704431950865366815470388295383915709243128759906220717341129511195454056628;
    
    uint256 constant IC2x = 20709921493540537772856922793580906037246774656859075127264934578933641231602;
    uint256 constant IC2y = 17177534413295040230233534031759289254021740828232931259472074520347379266971;
    
    uint256 constant IC3x = 1919682563887364831336471238759976910092185849979769654017386385702157256499;
    uint256 constant IC3y = 20411444332063614123120913346193454742754425904497662849624167786546352322628;
    
    uint256 constant IC4x = 1310848860349592572974323864744542492473748967241456351080793535821818578851;
    uint256 constant IC4y = 2884780933734146608978104217454012693453538156460941232185161046560184954555;
    
    uint256 constant IC5x = 20148638787644708910015680995512960129943990112505825780885470768524265228442;
    uint256 constant IC5y = 17327167803966072844137032115735969325243942197343194584529347150390962179485;
    
    uint256 constant IC6x = 11548384450240207411501526362493317690382504397365923119826706816721465916489;
    uint256 constant IC6y = 7957341174219194722337464907746509667091325310294744511574026102302148666219;
    
    uint256 constant IC7x = 3075101065578292086982878735072601054682493830270548906171625561548618837992;
    uint256 constant IC7y = 9600089533773299076145500316557358966042384263601662459967356481115639167564;
    
    uint256 constant IC8x = 1374282476176464196638032408881199450575674991763144614504274863977785327584;
    uint256 constant IC8y = 1416239149086988806836151531022441951010440424040069430257459876216883510489;
    
    uint256 constant IC9x = 8472929112328919070805163094151572568126815385083581561466927759673855091360;
    uint256 constant IC9y = 3153847305750520421348458872702658519490913235138464451091532616900837439127;
    
    uint256 constant IC10x = 13718910169746634421251616280615590581364497925801743967912289595430176779613;
    uint256 constant IC10y = 13112162894966725916368531124302857421166229586093573772485422163979947918796;
    
    uint256 constant IC11x = 16169102687164233294348056200244300083518078349008898855513982833734956159507;
    uint256 constant IC11y = 13559560846836403618701956128075585866342018189217913683967602919110392308507;
    
    uint256 constant IC12x = 3335194010258417035625729717014696339511694469486151614880480729119379043812;
    uint256 constant IC12y = 4496615068436144795992537170994226821880365537564320366353747759878449347867;
    
    uint256 constant IC13x = 10658010238801450237168431984552660070072869147247922631504904953510535436948;
    uint256 constant IC13y = 8832874893105147135372437652296334338832504057105814490081110533646942825648;
    
    uint256 constant IC14x = 16059557972969471670100546646240918510308164142204280294614670006615960329042;
    uint256 constant IC14y = 8319936871612423324457733112968243572293138146077423332751127876833208863481;
    
    uint256 constant IC15x = 12986936827274362534672915158654168248685839454904450182881119353818878800399;
    uint256 constant IC15y = 7400861484237944533348505858012395261502244397202908357740299157107848000111;
    
    uint256 constant IC16x = 21460898714046322730690338449484344237687639301564590464041723613044088077237;
    uint256 constant IC16y = 17093816342425178103609773082882434917788254826430662461971214033212322097626;
    
    uint256 constant IC17x = 1616190434699225577734136802718739162193960055067346108886172195118319677934;
    uint256 constant IC17y = 1612530117881189314306429725167197482079471985305607896329919136063723907604;
    
    uint256 constant IC18x = 18929201420072669704655442492506868482519940413395973728180076078382922373242;
    uint256 constant IC18y = 4065407617454870167930802563327201975435351732362467846917495226818080453962;
    
    uint256 constant IC19x = 2932783911699057142543657450380486209894244946249528875764982982124752936416;
    uint256 constant IC19y = 8816888935674817406143925846286633865554025309502384576428796610873884806264;
    
    uint256 constant IC20x = 1960891418224174875086063155680461992362664911894594208759719862146544510879;
    uint256 constant IC20y = 15399931217007939634539159203872779100880668743813339862019391821224972107069;
    
    uint256 constant IC21x = 2944980910511037965242510151755670601569423758607812571830109735298310521130;
    uint256 constant IC21y = 3111196641229037583639588544148755681497727386532328919023765738358370052175;
    
    uint256 constant IC22x = 18076129779413989196898634489299232987937565823798901700520459432110770689165;
    uint256 constant IC22y = 16972412899325733908295780520169364708393469069661465732021473860889070438024;
    
    uint256 constant IC23x = 1773425958473791310675860829317626976755819745857894176337457202406614047208;
    uint256 constant IC23y = 5805238937319684784645475698177590197058342600615124156990606053236064307317;
    
    uint256 constant IC24x = 5965341878869784913409675253327643476349946982983669806044762659337629174978;
    uint256 constant IC24y = 4533094313813674045324288625431403024637642687164905717999133187661753756822;
    
    uint256 constant IC25x = 13863090563402311636762215311383684106191434337944256419301897719918199662795;
    uint256 constant IC25y = 5313480559819674071674949351392568764544983872597512645282751590718100307035;
    
    uint256 constant IC26x = 3019458273767819335686891100370136503211328263509735300326239960850443559172;
    uint256 constant IC26y = 6811338921417293731431858685897496502093458024685997796944439237311502322876;
    
    uint256 constant IC27x = 9413311235249334046231362780354410278983307497736902197813503292393088304604;
    uint256 constant IC27y = 14318405006242326416151877548985538234646948325482815884137594239569990268436;
    
    uint256 constant IC28x = 11539052441412900298033672913551633723537246716762956293242337096367122698719;
    uint256 constant IC28y = 2059589943767491318548251468784905440530576021686020597248373709361461543506;
    
    uint256 constant IC29x = 19342270886526131137030505199003317519573109791122380304426085361106235768702;
    uint256 constant IC29y = 19390586339388171899191403382913551454145893453178131073206522839127767805081;
    
    uint256 constant IC30x = 9499996847305455142546025366242913144904471231868706380182236986822577549530;
    uint256 constant IC30y = 16134546129358783973038671463310097643294330184927084408908877657709292687127;
    
    uint256 constant IC31x = 21530388861549674007708981670878204360846523415868776081731625241816839791483;
    uint256 constant IC31y = 3616349429890753209862147355825728810606029321332509985461917686524112187221;
    
    uint256 constant IC32x = 16580877430461601602741865904038865322918688129816417877345375484642120914976;
    uint256 constant IC32y = 391046379330045962639745384366422454872601553478929528781803111830365417712;
    
    uint256 constant IC33x = 16921962897658654839665509349680009403604507756549520103942029316810940217613;
    uint256 constant IC33y = 10652193075683897161926301383628800964373276139350272075520624171948087962360;
    
    uint256 constant IC34x = 6156818533335504910166207526136521636257064740123208981590730970434683629825;
    uint256 constant IC34y = 1294194734261386292311297312581111752049587056068562865965586623463591452602;
    
    uint256 constant IC35x = 4828042001896718490119980939163340194623731445024713284118895210594522628726;
    uint256 constant IC35y = 7208198339087684513319456790702908815851755725453766340047795318110286382236;
    
    uint256 constant IC36x = 19510527888552200957224840173273801945769936572102471610061051254349199674413;
    uint256 constant IC36y = 2648692324794452105515048983505577723577158450642730933391563741168435626584;
    
    uint256 constant IC37x = 1442928608247689220527768714127631832412069407465547505933035731514263212057;
    uint256 constant IC37y = 6362452252591680192159268653003755233900565436295086708690880287898886744758;
    
    uint256 constant IC38x = 18241495268715032355022678409260137334083300497604685400638052619992941153410;
    uint256 constant IC38y = 18574709932179278069703019136227105687263758836235213563099169808105221099082;
    
    uint256 constant IC39x = 4917941006120596011074733364558449926933004922160508006006034942192484357669;
    uint256 constant IC39y = 1285705685726426925795549769400696510916128187052085461994621344375391157474;
    
    uint256 constant IC40x = 3853361421177726016999329847408782452773981303618243860977500160280098480005;
    uint256 constant IC40y = 14655080878399609942797338692382984411261127506162198049238536483924313795691;
    
    uint256 constant IC41x = 428987853258837136531060396170563569357659967773469340760393606715040223276;
    uint256 constant IC41y = 12570325475215137775615240337542066334857338084513521786418615374262310067015;
    
    uint256 constant IC42x = 18309801714104868055816095188348366548600596938486351778180129746649591259408;
    uint256 constant IC42y = 6045877318127972336838007211726272856573444740583266758457422707848335258475;
    
    uint256 constant IC43x = 16426481550639117583402937862432234195197585555255341844066026304670069294768;
    uint256 constant IC43y = 12558575502265872642685218237406427061260734225506914437345591023716442454813;
    
    uint256 constant IC44x = 1723245942007538708224887235944938933520520298035758207013871206286878064184;
    uint256 constant IC44y = 10311875795819392221009106492087487042535748820490024857273607297116395693499;
    
    uint256 constant IC45x = 1265406160734062661098232040477658570582390687964087214427741040695548476938;
    uint256 constant IC45y = 8536060209011569533779107149688441926338120798754324088975928581499381577916;
    
    uint256 constant IC46x = 8412167164435055450487994423206595155696172351022050645880437885982047676028;
    uint256 constant IC46y = 10275624142015530576600002762355308690767081120717022547081127444530930818656;
    
    uint256 constant IC47x = 12789892494088374519677392209018050324037968514249797623804221593321340701623;
    uint256 constant IC47y = 18992971240327953328262376922475135806941128734738707412677898033044883399172;
    
    uint256 constant IC48x = 19358758119611257603365848029509374026405639191370244539447932314094997244913;
    uint256 constant IC48y = 18027745846521288992239888539203778449142276737383394168069072569728322821033;
    
    uint256 constant IC49x = 4396974003844442838530178255357030840873565151423754079452843631972559098523;
    uint256 constant IC49y = 7407495299960391976347333402013103624507797843861189833644684470973008350465;
    
    uint256 constant IC50x = 9305158659273978574347827088324499040496070754594715203165141673460471511428;
    uint256 constant IC50y = 8893055936838192399927499675640014851211453622969267099282713742094996960289;
    
    uint256 constant IC51x = 4004421599445629386387662680375456199243301890678188697119416930303986546745;
    uint256 constant IC51y = 9812246280570600697263365094878831769005259371631303884632966454620676927363;
    
    uint256 constant IC52x = 7225697831378425959223509066954805583235115634259765590896626823780356094167;
    uint256 constant IC52y = 3140804004981447154592946452655187412512939024416777666026351474889569685133;
    
    uint256 constant IC53x = 11713486848388970006461954479953477669664328478685749654448233406228492527607;
    uint256 constant IC53y = 21106353988791684587337277189618867540836247157739138642687971961440771451955;
    
    uint256 constant IC54x = 15743975518805680998994334827082191047283873491316548234265822797283076900115;
    uint256 constant IC54y = 16100747976574635071346073530611189736197052627689529936505983284745319016550;
    
    uint256 constant IC55x = 7968211819269635622251240965808926416807120092272959097215430725658694353926;
    uint256 constant IC55y = 290611586103058928946287272760793455022613054081477917089412644617268441544;
    
    uint256 constant IC56x = 5497535283742145725408333786198258563765177329495793400287088833822460619589;
    uint256 constant IC56y = 13990447407008654997891858005714806938596753815452674041382326459897574630642;
    
    uint256 constant IC57x = 21551221395051735106146050168185995643686723212300528514948105510709015597565;
    uint256 constant IC57y = 3010820354779330462870738552334648652609509253015380687424364842109051831208;
    
    uint256 constant IC58x = 21055144836372268734159874535280980912111568900487550069377349160888277609686;
    uint256 constant IC58y = 9403502891261179745152244684553617183079273734709973561346044885923820274268;
    
    uint256 constant IC59x = 644755791512858684444535627113953822790587003932006166208510248582999853459;
    uint256 constant IC59y = 13139790086181822528796172026776820570796562546227293728469615899278070554160;
    
    uint256 constant IC60x = 6725016972108267455701138847289063932000277703234367252597638956595093086073;
    uint256 constant IC60y = 13341730485954583119039655819469048959544142884801974250922782996800726034146;
    
    uint256 constant IC61x = 14194338528036582957596902482599618332132406934511113318858954366640432879513;
    uint256 constant IC61y = 6061770439344639772945639478286060619506258321354890780646994375903868130360;
    
    uint256 constant IC62x = 12755142399088220484276173224702599108578221128864115724826184459398402686492;
    uint256 constant IC62y = 14282661132964156338498205154249301789813916879292317368710554599268894715095;
    
    uint256 constant IC63x = 15133574682445412881534271104982918802894028598409671138631965896699033761966;
    uint256 constant IC63y = 5788788686468022201860580859288532398371792112282010133767723090790469443206;
    
    uint256 constant IC64x = 13278678156200165709832433809411614565470076620189992325833418503149677368645;
    uint256 constant IC64y = 4440830668084513378819384097965819072140127294337234887713973711120359470487;
    
    uint256 constant IC65x = 4509130488733691011439289153411326875175305836880792986711227563741046583487;
    uint256 constant IC65y = 15654789212689237856902861147842080265295517907616210238680659951382266981633;
    
    uint256 constant IC66x = 3968136740167471213377254771668378339410419005443202926920404650906785781910;
    uint256 constant IC66y = 13171384325987164802440252387785515741487433189655042960077621623520843116781;
    
    uint256 constant IC67x = 16036693217452409687908665555755795358413991085560766692875750461678650623172;
    uint256 constant IC67y = 15767394615402816610636137572833470287425426948407479989189509262123089353249;
    
    uint256 constant IC68x = 11955147328347489029121745205286049819678960286506207765633229006336216994881;
    uint256 constant IC68y = 8417085293231041535883715255873388524357216720181100003138999616567114756342;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[68] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                
                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))
                
                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))
                
                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))
                
                g1_mulAccC(_pVk, IC23x, IC23y, calldataload(add(pubSignals, 704)))
                
                g1_mulAccC(_pVk, IC24x, IC24y, calldataload(add(pubSignals, 736)))
                
                g1_mulAccC(_pVk, IC25x, IC25y, calldataload(add(pubSignals, 768)))
                
                g1_mulAccC(_pVk, IC26x, IC26y, calldataload(add(pubSignals, 800)))
                
                g1_mulAccC(_pVk, IC27x, IC27y, calldataload(add(pubSignals, 832)))
                
                g1_mulAccC(_pVk, IC28x, IC28y, calldataload(add(pubSignals, 864)))
                
                g1_mulAccC(_pVk, IC29x, IC29y, calldataload(add(pubSignals, 896)))
                
                g1_mulAccC(_pVk, IC30x, IC30y, calldataload(add(pubSignals, 928)))
                
                g1_mulAccC(_pVk, IC31x, IC31y, calldataload(add(pubSignals, 960)))
                
                g1_mulAccC(_pVk, IC32x, IC32y, calldataload(add(pubSignals, 992)))
                
                g1_mulAccC(_pVk, IC33x, IC33y, calldataload(add(pubSignals, 1024)))
                
                g1_mulAccC(_pVk, IC34x, IC34y, calldataload(add(pubSignals, 1056)))
                
                g1_mulAccC(_pVk, IC35x, IC35y, calldataload(add(pubSignals, 1088)))
                
                g1_mulAccC(_pVk, IC36x, IC36y, calldataload(add(pubSignals, 1120)))
                
                g1_mulAccC(_pVk, IC37x, IC37y, calldataload(add(pubSignals, 1152)))
                
                g1_mulAccC(_pVk, IC38x, IC38y, calldataload(add(pubSignals, 1184)))
                
                g1_mulAccC(_pVk, IC39x, IC39y, calldataload(add(pubSignals, 1216)))
                
                g1_mulAccC(_pVk, IC40x, IC40y, calldataload(add(pubSignals, 1248)))
                
                g1_mulAccC(_pVk, IC41x, IC41y, calldataload(add(pubSignals, 1280)))
                
                g1_mulAccC(_pVk, IC42x, IC42y, calldataload(add(pubSignals, 1312)))
                
                g1_mulAccC(_pVk, IC43x, IC43y, calldataload(add(pubSignals, 1344)))
                
                g1_mulAccC(_pVk, IC44x, IC44y, calldataload(add(pubSignals, 1376)))
                
                g1_mulAccC(_pVk, IC45x, IC45y, calldataload(add(pubSignals, 1408)))
                
                g1_mulAccC(_pVk, IC46x, IC46y, calldataload(add(pubSignals, 1440)))
                
                g1_mulAccC(_pVk, IC47x, IC47y, calldataload(add(pubSignals, 1472)))
                
                g1_mulAccC(_pVk, IC48x, IC48y, calldataload(add(pubSignals, 1504)))
                
                g1_mulAccC(_pVk, IC49x, IC49y, calldataload(add(pubSignals, 1536)))
                
                g1_mulAccC(_pVk, IC50x, IC50y, calldataload(add(pubSignals, 1568)))
                
                g1_mulAccC(_pVk, IC51x, IC51y, calldataload(add(pubSignals, 1600)))
                
                g1_mulAccC(_pVk, IC52x, IC52y, calldataload(add(pubSignals, 1632)))
                
                g1_mulAccC(_pVk, IC53x, IC53y, calldataload(add(pubSignals, 1664)))
                
                g1_mulAccC(_pVk, IC54x, IC54y, calldataload(add(pubSignals, 1696)))
                
                g1_mulAccC(_pVk, IC55x, IC55y, calldataload(add(pubSignals, 1728)))
                
                g1_mulAccC(_pVk, IC56x, IC56y, calldataload(add(pubSignals, 1760)))
                
                g1_mulAccC(_pVk, IC57x, IC57y, calldataload(add(pubSignals, 1792)))
                
                g1_mulAccC(_pVk, IC58x, IC58y, calldataload(add(pubSignals, 1824)))
                
                g1_mulAccC(_pVk, IC59x, IC59y, calldataload(add(pubSignals, 1856)))
                
                g1_mulAccC(_pVk, IC60x, IC60y, calldataload(add(pubSignals, 1888)))
                
                g1_mulAccC(_pVk, IC61x, IC61y, calldataload(add(pubSignals, 1920)))
                
                g1_mulAccC(_pVk, IC62x, IC62y, calldataload(add(pubSignals, 1952)))
                
                g1_mulAccC(_pVk, IC63x, IC63y, calldataload(add(pubSignals, 1984)))
                
                g1_mulAccC(_pVk, IC64x, IC64y, calldataload(add(pubSignals, 2016)))
                
                g1_mulAccC(_pVk, IC65x, IC65y, calldataload(add(pubSignals, 2048)))
                
                g1_mulAccC(_pVk, IC66x, IC66y, calldataload(add(pubSignals, 2080)))
                
                g1_mulAccC(_pVk, IC67x, IC67y, calldataload(add(pubSignals, 2112)))
                
                g1_mulAccC(_pVk, IC68x, IC68y, calldataload(add(pubSignals, 2144)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            
            checkField(calldataload(add(_pubSignals, 608)))
            
            checkField(calldataload(add(_pubSignals, 640)))
            
            checkField(calldataload(add(_pubSignals, 672)))
            
            checkField(calldataload(add(_pubSignals, 704)))
            
            checkField(calldataload(add(_pubSignals, 736)))
            
            checkField(calldataload(add(_pubSignals, 768)))
            
            checkField(calldataload(add(_pubSignals, 800)))
            
            checkField(calldataload(add(_pubSignals, 832)))
            
            checkField(calldataload(add(_pubSignals, 864)))
            
            checkField(calldataload(add(_pubSignals, 896)))
            
            checkField(calldataload(add(_pubSignals, 928)))
            
            checkField(calldataload(add(_pubSignals, 960)))
            
            checkField(calldataload(add(_pubSignals, 992)))
            
            checkField(calldataload(add(_pubSignals, 1024)))
            
            checkField(calldataload(add(_pubSignals, 1056)))
            
            checkField(calldataload(add(_pubSignals, 1088)))
            
            checkField(calldataload(add(_pubSignals, 1120)))
            
            checkField(calldataload(add(_pubSignals, 1152)))
            
            checkField(calldataload(add(_pubSignals, 1184)))
            
            checkField(calldataload(add(_pubSignals, 1216)))
            
            checkField(calldataload(add(_pubSignals, 1248)))
            
            checkField(calldataload(add(_pubSignals, 1280)))
            
            checkField(calldataload(add(_pubSignals, 1312)))
            
            checkField(calldataload(add(_pubSignals, 1344)))
            
            checkField(calldataload(add(_pubSignals, 1376)))
            
            checkField(calldataload(add(_pubSignals, 1408)))
            
            checkField(calldataload(add(_pubSignals, 1440)))
            
            checkField(calldataload(add(_pubSignals, 1472)))
            
            checkField(calldataload(add(_pubSignals, 1504)))
            
            checkField(calldataload(add(_pubSignals, 1536)))
            
            checkField(calldataload(add(_pubSignals, 1568)))
            
            checkField(calldataload(add(_pubSignals, 1600)))
            
            checkField(calldataload(add(_pubSignals, 1632)))
            
            checkField(calldataload(add(_pubSignals, 1664)))
            
            checkField(calldataload(add(_pubSignals, 1696)))
            
            checkField(calldataload(add(_pubSignals, 1728)))
            
            checkField(calldataload(add(_pubSignals, 1760)))
            
            checkField(calldataload(add(_pubSignals, 1792)))
            
            checkField(calldataload(add(_pubSignals, 1824)))
            
            checkField(calldataload(add(_pubSignals, 1856)))
            
            checkField(calldataload(add(_pubSignals, 1888)))
            
            checkField(calldataload(add(_pubSignals, 1920)))
            
            checkField(calldataload(add(_pubSignals, 1952)))
            
            checkField(calldataload(add(_pubSignals, 1984)))
            
            checkField(calldataload(add(_pubSignals, 2016)))
            
            checkField(calldataload(add(_pubSignals, 2048)))
            
            checkField(calldataload(add(_pubSignals, 2080)))
            
            checkField(calldataload(add(_pubSignals, 2112)))
            
            checkField(calldataload(add(_pubSignals, 2144)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
