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

contract Groth16Verifier {
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

    
    uint256 constant IC0x = 18988666432660310943956167876509557505239228789168706280346858218900612013444;
    uint256 constant IC0y = 16253834551164753997716925098007099279841383449080364785958010302688454780775;
    
    uint256 constant IC1x = 17642144097748297656386439239694617243322176695477277759737531185822587674686;
    uint256 constant IC1y = 6841119697305780433582958110661353843385831690046301513907846402341254166333;
    
    uint256 constant IC2x = 18648668620755042186374489945840103314258318931293263538105893877106832596489;
    uint256 constant IC2y = 13597985609552691705146445766319069258096725112305432892565858964704733507453;
    
    uint256 constant IC3x = 1865427592803767556110990264711102560656204331438909664134354212264968932405;
    uint256 constant IC3y = 8384461216747832453511499957270808383563156855484992548587627962499319801255;
    
    uint256 constant IC4x = 2279735737536818824667316330942306771595658178117515799282365469193898553404;
    uint256 constant IC4y = 14439044683851490404571561666958561050044196587222301228261311748868610036450;
    
    uint256 constant IC5x = 11387211484302116931436863020442648032980856949036583849256084792273522055454;
    uint256 constant IC5y = 20491364386101839399676679787654372772953015257920319528168006894472932118141;
    
    uint256 constant IC6x = 7587999288469952477580049630562082226942781037431432199844447134420599630148;
    uint256 constant IC6y = 8121842103746485736886446324803991775287752622263959142957591767579559610193;
    
    uint256 constant IC7x = 19076167493912362541108606047190621986836459465477326580007373709984374112910;
    uint256 constant IC7y = 8738290293587659398867654034023902343949656979693758650591075881852343081520;
    
    uint256 constant IC8x = 6891084547391826619942867126203537905628188189274534906668158559221283357222;
    uint256 constant IC8y = 12259166899373661069766853458138791292326198554087278665156804487397771455981;
    
    uint256 constant IC9x = 11735880666994843688356623677190273203181713961101218427863191958632930575847;
    uint256 constant IC9y = 17004599762774660639908854010601851857636740437253949538279153847775961435982;
    
    uint256 constant IC10x = 11805685243755627101305748473491373917402284857411566330721197534834600896201;
    uint256 constant IC10y = 6603832027414837035104994442097786097587521242015608344666147536604344734254;
    
    uint256 constant IC11x = 21014239920433289086511713864214867927935899079163365932521379503313312484460;
    uint256 constant IC11y = 6723925005067463381870071014335324825976261327865774465857002205201106610026;
    
    uint256 constant IC12x = 5826846781137636128426594737155951207337680105123155379382803560908836375771;
    uint256 constant IC12y = 13661220100965380090021618267591715824279796996817102329419568637614308414566;
    
    uint256 constant IC13x = 16407954252887932277255351459066830892711475322302085958929147969336772583831;
    uint256 constant IC13y = 21060531822041330736469506332212677965895736051016424071652871981084074076266;
    
    uint256 constant IC14x = 2038536913205203014757470037722468945870067228821052716252549792408574907587;
    uint256 constant IC14y = 2732215357420077530483107934494781866869179843307988348333054273111192100736;
    
    uint256 constant IC15x = 7106736716282992506458564445579763187312092933960040343774330444930744478493;
    uint256 constant IC15y = 16926030728228871544939821808564602764379742840979446452878994007360741948119;
    
    uint256 constant IC16x = 18882403283690768847463920792397829889258558861163176278993076269025306344446;
    uint256 constant IC16y = 6427753558896860292477010925693590884299103139889612047745005804143585905899;
    
    uint256 constant IC17x = 196403232639009111427047213211414315450911656091776679373566845163084519520;
    uint256 constant IC17y = 7420558982369683960258943927242801420860367902173852200514441928000350716537;
    
    uint256 constant IC18x = 10477561125333477313106362465213336433658273756136081129386219355331703870928;
    uint256 constant IC18y = 11051881551461987592165793075306248164939968641667918022699212583524779324240;
    
    uint256 constant IC19x = 8984054136084470082298480530677473063035899838943817718344378910713837493243;
    uint256 constant IC19y = 18715335174484724551485360270772615521635767584558225403791883481701013645061;
    
    uint256 constant IC20x = 18204651502654913756531847593223354926081581649265836240187854770340190892273;
    uint256 constant IC20y = 2475251895046566347360012990592624649798787851494765587647999459023788650655;
    
    uint256 constant IC21x = 10382133002093704720821570564340885216397570622732300591120750771819358646224;
    uint256 constant IC21y = 14771585063407383226373580532687703649506239633014351712643106812285825677127;
    
    uint256 constant IC22x = 15700082804281446047504681862027442831142793994540742012798099428019879954396;
    uint256 constant IC22y = 12940204499622114671891829262187642836295702718523515442693234678264550703196;
    
    uint256 constant IC23x = 5715562132191285571830075794228490007261248030092654115538615497601897631524;
    uint256 constant IC23y = 6038482725633459678415252321946949763219385942175045757054639738005637367258;
    
    uint256 constant IC24x = 11498707973298936858716014725244871576202838619021379597015664680909217445032;
    uint256 constant IC24y = 790520873502951204205918869371561114373168504568325464408182695243359608715;
    
    uint256 constant IC25x = 19254154690545334975756629405298108208061297542581857707253348653065966238547;
    uint256 constant IC25y = 10327914980065361884543126382875045319506344069522711058674951042683549580503;
    
    uint256 constant IC26x = 3663793718388881858659510051821456087849348375618166185805918068372152822876;
    uint256 constant IC26y = 12236011722726288450176604829986262710255967661383680734369256147456228541506;
    
    uint256 constant IC27x = 8893950058120634310868149134498524443258088500149867166442770023094582906603;
    uint256 constant IC27y = 11980605566581986233520666642705052507297575893944225480118126524746064260569;
    
    uint256 constant IC28x = 6941613454131876786422932805618126481581355792087106766533431228772632804935;
    uint256 constant IC28y = 12059230814505041107408704538991672138648505162334734064011003235275345280932;
    
    uint256 constant IC29x = 21509730405352496231749143848094413932944976689656475127038784288032079967455;
    uint256 constant IC29y = 15718682888017891736156350779288440047933388573336519588281608509876181392531;
    
    uint256 constant IC30x = 7000729456104093307798285551256887419374787470946143109733883249638356796879;
    uint256 constant IC30y = 3040447667402553039973604937814095888332193058513622789740532880681326389256;
    
    uint256 constant IC31x = 4482647949732879721094963368176104807156340225688556113420610296291413823360;
    uint256 constant IC31y = 11143386081216736471838727538554422170373408750712489411299669561682463475571;
    
    uint256 constant IC32x = 11877642103983902763675290212840868801185161011660324726797670107896463123283;
    uint256 constant IC32y = 11662454176205565051915374345737827544257993991525199817175539983721769226213;
    
    uint256 constant IC33x = 13514586505837985749064419304096326049153078465991450921641035340467577041057;
    uint256 constant IC33y = 9699354273423396718049616621404955174181932613998067562069000613998904191386;
    
    uint256 constant IC34x = 14015697850356451003567877558585513086299782442153432415904507869567904406293;
    uint256 constant IC34y = 20973235836373817699285653263637580048006974216140948870033989360410211557954;
    
    uint256 constant IC35x = 14539836135219674697745797133509388522942818090488446731307493129241395148474;
    uint256 constant IC35y = 14946750514360941480803978152708831116096776173593100834673246870329987475193;
    
    uint256 constant IC36x = 16197659673281249949560669311950694319304259004675552323943665821995390405647;
    uint256 constant IC36y = 10624605217027128491166254396254550714204648209048539638140052456171489792728;
    
    uint256 constant IC37x = 4621226112969045602908196428362103166510759049361794826809621788314968432807;
    uint256 constant IC37y = 12294200313449554505592616516598053121540118435280634024164377440765147743677;
    
    uint256 constant IC38x = 4610825269034410998540147198532098773206097341061604483355263752895816624310;
    uint256 constant IC38y = 5603101743677665129270717407173654714774660847676017984116807257657653527468;
    
    uint256 constant IC39x = 6467043043804548884408373112817645772108298312091045584501727970919330695642;
    uint256 constant IC39y = 21828876708039404214590173068335041575806727713687564702728601368797353969385;
    
    uint256 constant IC40x = 6855237380018513070890316545285123099921921008142975502818586281485432630847;
    uint256 constant IC40y = 19351594329871533072025855432122347893442174991097580599328222490414724002379;
    
    uint256 constant IC41x = 11409626741533846910658075398648345203915591013450280491869892933345480523936;
    uint256 constant IC41y = 8509797629615195050654480253386537876451759139981875994387553693836834532922;
    
    uint256 constant IC42x = 13067490711645928081465329497992876277275171923865151670927122540097722311709;
    uint256 constant IC42y = 5918681356640772631848318990825813637063633770177553613253912495136076451286;
    
    uint256 constant IC43x = 11064147000388721316884447331305284620902891317313232219267323615529520620376;
    uint256 constant IC43y = 19877585624878157552611194254157732599369604518818328748942367253344172565713;
    
    uint256 constant IC44x = 4010095286624502689546937689039023011126208061154941895100536616869458571881;
    uint256 constant IC44y = 11809518067623061846817481286921944379310161954208776065371402129847243757811;
    
    uint256 constant IC45x = 19397350150436711387090673134490287436497909091914464123566723358548199697225;
    uint256 constant IC45y = 13589246221843492274343945017150313632594926450570191519365643601644070771136;
    
    uint256 constant IC46x = 14892549210888194148051141857830129002141887843803712526095559312791660348939;
    uint256 constant IC46y = 1046600894226443052884915426074604081891060471822046103906850634674079756038;
    
    uint256 constant IC47x = 16229667952037701569087300169649979330817402259980689312895317803286281436830;
    uint256 constant IC47y = 4868803187289085421310716536411590568996313582918577790979772279140664777029;
    
    uint256 constant IC48x = 4558665838367678882570018663024515521398644156524736206727874574667877019287;
    uint256 constant IC48y = 9433696384657375219396140499172713004973875081310919962088567692893770293644;
    
    uint256 constant IC49x = 20085907297936451361512701647913896298183379072585265838738976325973151890197;
    uint256 constant IC49y = 9725784389388801440324680661511982305824958554649507299066380149879126226507;
    
    uint256 constant IC50x = 9344709337535486154664654925671174228534620631738891957302330051235175474928;
    uint256 constant IC50y = 6312810555784175244800474069568269184007674038150847100870734504327648470645;
    
    uint256 constant IC51x = 890454711308793831543910653019023618958835878851238906643967809077908961475;
    uint256 constant IC51y = 9383455918507249005151319545438944862128440161524383137586017626728576160104;
    
    uint256 constant IC52x = 3698539844897574420002517745329169266721493775771273713868960686187017950887;
    uint256 constant IC52y = 21717573389627983466497981596502138650726502458127764552404886974350431680639;
    
    uint256 constant IC53x = 13566309552666268825014036751377751962786126412127230475508887041699112625739;
    uint256 constant IC53y = 20784106523420839698562529005337709863734028366629269199193291630304365684313;
    
    uint256 constant IC54x = 8176554612475315499792019087511948768867051855150712064544690237981413547780;
    uint256 constant IC54y = 21377257644580221471540176522292227017210073748330956671970235891040781995631;
    
    uint256 constant IC55x = 140789023209285099670367726735099937415771286631651689453229957559393883939;
    uint256 constant IC55y = 14331095636222369209698133480359640863425269045834000072247130451790047293106;
    
    uint256 constant IC56x = 17086916061495339320505376849950816617233129147915406713620790763934819468725;
    uint256 constant IC56y = 15062024045675848091388824568016433046558364852262631420483405180855176891251;
    
    uint256 constant IC57x = 11472427969124673503577799727416847310515857621557801735177932546019033503998;
    uint256 constant IC57y = 12339499304048703272222511313765690649413966111995806643483388231521915199457;
    
    uint256 constant IC58x = 17505009232784074658187988644819264748250243904807989312210274141890684762494;
    uint256 constant IC58y = 17398492265548121348886220726663210764915351196039254241733427014870372791881;
    
    uint256 constant IC59x = 13805583500858133981867747921823502125274881821519949038272358392489785368276;
    uint256 constant IC59y = 4217446254916031183978139850790235971804490447777394941671847265769526036781;
    
    uint256 constant IC60x = 7444187441090695528844606785169904601643053000283040175870908472341301502963;
    uint256 constant IC60y = 13449240169357121900094334928430671752433523046074501058031575196624666159397;
    
    uint256 constant IC61x = 11853624978621224899631217127296008897565640337956722626192201133667120194755;
    uint256 constant IC61y = 7196639421387962662348896875092908924499022358610663985068582821159271352559;
    
    uint256 constant IC62x = 5236394239887214549668103308623619030515424296703396576270716189898487261227;
    uint256 constant IC62y = 21851589287257682759964784453752901925194972935424490979867468501203099230516;
    
    uint256 constant IC63x = 8963301718435457094835253713668945597722504620352377597934061932673866202445;
    uint256 constant IC63y = 8282203191838985087660605817993720595774008938799407883856973251079121619205;
    
    uint256 constant IC64x = 7650969031762360301517246890403225598726252776907533050845533619694873297429;
    uint256 constant IC64y = 1283200009164583129436237478173542133014247611384041217556463912364382340543;
    
    uint256 constant IC65x = 17721476756030143351316907818462319161198765876391675075737906101460611579109;
    uint256 constant IC65y = 12561056850635785406995931065041170024604424982508817319346157530519088715366;
    
    uint256 constant IC66x = 11988111160567870997867660642883058514333015462051442413764683199402490863371;
    uint256 constant IC66y = 18783726410605399497371354769866834795284519330349489633614026016825621256073;
    
    uint256 constant IC67x = 16634602088506420169125110888675237834714966147243737521376201758404986864899;
    uint256 constant IC67y = 5911183059524848466465692091660788161295245017855587416186324531697512519450;
    
    uint256 constant IC68x = 5446746946093761366521016337270971805859455886026871663383991971814835622516;
    uint256 constant IC68y = 2953667146013034916337450155590071985091975854789002808476563423458349941733;
    
 
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
