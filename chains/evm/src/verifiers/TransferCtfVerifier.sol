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

contract TransferCtfVerifier {
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

    
    uint256 constant IC0x = 18475768107343177985131002102945651293125112048368399281614268225568468007032;
    uint256 constant IC0y = 11681456555135614163339298030200255882375748155605296747811888388575596297151;
    
    uint256 constant IC1x = 8855039882084116007457984267157525524244479253238031717748403932140734996234;
    uint256 constant IC1y = 3689802112361207633466990159891183613802376627116780868918899734626240309266;
    
    uint256 constant IC2x = 10843747537677352647991169766041272302506483141270243816480414456087667293439;
    uint256 constant IC2y = 12677995403663720141485292840497313356535331988467641593668883368288724634202;
    
    uint256 constant IC3x = 18973198115414536273923472799491414166072711152337637978348339144122470941040;
    uint256 constant IC3y = 11615916223950699618766053503253343131279378950098994251357857078003426966689;
    
    uint256 constant IC4x = 10294688304543314359672032629914206071352540414555505708454754274159467998650;
    uint256 constant IC4y = 18353321154926166666163512285326398060312979481515133957379824652348507412032;
    
    uint256 constant IC5x = 12277187972946581927401980768541290208815963041810564793614115293734663676151;
    uint256 constant IC5y = 7168595564659480473096020340872414556591910397221505351490109354295279491007;
    
    uint256 constant IC6x = 12168900569140981418728682011368941733565727279653178206497785538482002033973;
    uint256 constant IC6y = 3851495076120327478313109337106607379653199572302436265461772175163004836553;
    
    uint256 constant IC7x = 1076815485028060428715514566776296804612496221726404431052033257903345165465;
    uint256 constant IC7y = 3813410215386630471621721151487938607884963513688294768893393111890864307346;
    
    uint256 constant IC8x = 7517868611691065955878987456011293198481786036775542983008012121445745341243;
    uint256 constant IC8y = 4307838976928605682712729196787650476008790197120447914080690720368193072874;
    
    uint256 constant IC9x = 20159927668847648765939428780854900444716045810776824859703423974029943125518;
    uint256 constant IC9y = 7575180950991765153240784612069344251847858576456060751128043364845240127047;
    
    uint256 constant IC10x = 2008963275908033172339997004780373634861943018515738275081284358541809155869;
    uint256 constant IC10y = 5403475990212907378334173377718136408255057786072681100388620593022493210026;
    
    uint256 constant IC11x = 17817520239675685515672449441607931855733357253928302751876872530426646745737;
    uint256 constant IC11y = 21640791397491125612571826079311400250038450594794215831299971542863868207848;
    
    uint256 constant IC12x = 8693137021693048855216533219822519249254871672826005742399717709283941900813;
    uint256 constant IC12y = 20160386475108581482005944031291929398996433929022289999749947619621133772928;
    
    uint256 constant IC13x = 8191813317911937706695132556267176594674494341018685948641211301529181199886;
    uint256 constant IC13y = 11741037096831722400968701131735779652833308642548536680413637078681831937363;
    
    uint256 constant IC14x = 19539253662279926535116253952982081710692473897040921641990844128762667110014;
    uint256 constant IC14y = 11646155098437111738138968102946990686280511176200206201564302740712062370466;
    
    uint256 constant IC15x = 6257927084000615615857293256477086654848837133804146281224172368051846104594;
    uint256 constant IC15y = 17573947113709773734070364242005707060301185583512488984292492612421330676172;
    
    uint256 constant IC16x = 11473487554694889683643587888880567459273802526103618705538082875207495926182;
    uint256 constant IC16y = 17276658191631683419558572641623609808793436987725010430984127770870765527711;
    
    uint256 constant IC17x = 14564461518430619279157941214436879674713659625295506184914516547358043326041;
    uint256 constant IC17y = 10747890076112173764517380008599674884948990021004970598055294266029047597150;
    
    uint256 constant IC18x = 764468191891914468075634737756103058697098796557968861432443651944725067960;
    uint256 constant IC18y = 180501701898111744480535179731570489368949481690411340103999592966468151791;
    
    uint256 constant IC19x = 1504194892730541188071967510237745362954544794764720340578974638182039614628;
    uint256 constant IC19y = 2680128314869644141388269623902981435281809628700797561797272374829318767193;
    
    uint256 constant IC20x = 7547429463452862843780660751326131025054565251559145087824558819153774779628;
    uint256 constant IC20y = 2423717551493798242673390472830608946122663546097473926384157413585082691883;
    
    uint256 constant IC21x = 11598911526427326066759776802606346566935544961134619034818784334022702737653;
    uint256 constant IC21y = 5348847525292782191951627904883545330952584438950280365392357749262726723597;
    
    uint256 constant IC22x = 12739548339832649305268795161408612923271693138295590756831344492620805002349;
    uint256 constant IC22y = 5552964077395645552148268743441575461463971656350907702831056447840303506076;
    
    uint256 constant IC23x = 20492468275155920706765565520241583201251057177542819732067431146987989439914;
    uint256 constant IC23y = 603493216234883947050085268743083198525636875384083954146117131584558607447;
    
    uint256 constant IC24x = 9137931529573830026280788479624002376877173874961740914448224830039485572128;
    uint256 constant IC24y = 2610643526416002230559879612881750999922744374203889657719084399561809702224;
    
    uint256 constant IC25x = 19578287332519681164751148388674425809297271667078190109426263665302147746041;
    uint256 constant IC25y = 10465407154087974759620844576141664592133365782570234516802117239999019106689;
    
    uint256 constant IC26x = 18244805635819058442219663970180477246517244057947519203242580277984441568206;
    uint256 constant IC26y = 13799401363654722318362464963789852757390265640529020073489250157054585405784;
    
    uint256 constant IC27x = 10322966155945716121889714941375135412313367289062817669089472439831708560100;
    uint256 constant IC27y = 2970174764136697950495712740612266235893374997706699522518968720365413690810;
    
    uint256 constant IC28x = 10817612160914514717629006493472084780730728852810867275306902569307467293022;
    uint256 constant IC28y = 12848660301240748819867786205206130735188795960163956273964234443873563378671;
    
    uint256 constant IC29x = 19574525364363268236022495460944966058956570026060307495789438794377033650329;
    uint256 constant IC29y = 690760959425858578198759402522802536294468857194773128773346954274367365060;
    
    uint256 constant IC30x = 3276183531420333137205477671771896393325230295089553069031174775005982658702;
    uint256 constant IC30y = 18510439689150621083825555563851342242613392197537227292348699255198676204272;
    
    uint256 constant IC31x = 1476646689754539905310961641276474624595913118004461512334882714908818308379;
    uint256 constant IC31y = 20342314109841859006145319614452931651386870690954082584648381847469391674979;
    
    uint256 constant IC32x = 20510576922262384755256339878016287514486580327678970476623969676003983639418;
    uint256 constant IC32y = 20269169812828073185527347122648821097494961285675599384233178043066686335597;
    
    uint256 constant IC33x = 8448102590125253729717916434421923658413756613487725410148313498280342664291;
    uint256 constant IC33y = 21209235526624719982000104326993788295832181281803144326805967799010964995998;
    
    uint256 constant IC34x = 17545472309579074709196258197639846845252929359646437107501064002527100957183;
    uint256 constant IC34y = 17744302677873377595678004284464360159642675938581036733878291853022874940251;
    
    uint256 constant IC35x = 7222115423380014994650157685529950964080680534695778007601373418278446413357;
    uint256 constant IC35y = 6289747782310520540300526306796061472397330589991295657156173695047114626323;
    
    uint256 constant IC36x = 2212838249755721145381920113384869551415048182632432982564256914916802073637;
    uint256 constant IC36y = 7212277090359762360715604538197070220041387084035256200686480439048641530268;
    
    uint256 constant IC37x = 16232893234852171140438273569095883530915663522940829738057379667714424270825;
    uint256 constant IC37y = 5307781121674889421555459424063608564246730735675201214461608196565193733297;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[37] calldata _pubSignals) public view returns (bool) {
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
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
