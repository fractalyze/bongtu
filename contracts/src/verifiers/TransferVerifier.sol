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

contract TransferVerifier {
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

    
    uint256 constant IC0x = 1843818638757759262675514054640128836626157800170992201099306876063502964903;
    uint256 constant IC0y = 15702482051707099681076361212906043305765391766312633097759551899189701344649;
    
    uint256 constant IC1x = 14588943101963558249659050274245294255468585376882027591652534476270277223412;
    uint256 constant IC1y = 14562344784955293960242215651300978793869157597322635363659075965006739185156;
    
    uint256 constant IC2x = 6755250712857063049853353204942001956747050715574195458288988294492986809656;
    uint256 constant IC2y = 7509281993287779413162304299882132683693677194038161968811440266294031967567;
    
    uint256 constant IC3x = 6077133657931340038940032740199208682719019310903847258640468781096160252545;
    uint256 constant IC3y = 18948706948434220736843333189807397625055268070511223013500196947495091750616;
    
    uint256 constant IC4x = 2182892753989767895907741746974391820171180638199983061152010809538126046990;
    uint256 constant IC4y = 8876109530019620248632800161379196719930867302280313013967393952196001124697;
    
    uint256 constant IC5x = 1246727088195182231044796854392384751068403042938410108185251509904029667835;
    uint256 constant IC5y = 12834454974930530138220843350259441675686101114441586554069269110634499377423;
    
    uint256 constant IC6x = 11315448109620565239075154830616570456899538938157482329736814211089428301247;
    uint256 constant IC6y = 7770190547094625805766669146413967339206266630325313274645442122646797647366;
    
    uint256 constant IC7x = 10961696501069412047827844674629006515234051091399123872801771479117463289704;
    uint256 constant IC7y = 8986090143692753776928129953744061792837508393088740705763328822545333112296;
    
    uint256 constant IC8x = 2594220994712963803639540862849695546618245267573101408508130626801055046225;
    uint256 constant IC8y = 18669166342232072368949882985588082175906933077271806454325522238212442049850;
    
    uint256 constant IC9x = 17635973749701804638456149131489058680825434179203210364825067520684864015382;
    uint256 constant IC9y = 19247982915376516999065225582287957058171196033178572981709391049615589404680;
    
    uint256 constant IC10x = 18781710146799604446703771786733783486737730299946774276926086580266807446434;
    uint256 constant IC10y = 7200330172476944661191896919547771691685968097357892874250801688007034559392;
    
    uint256 constant IC11x = 4190455397115631157504094198772078394855306945301345137249056182780740232179;
    uint256 constant IC11y = 10547654849252667356689427890385527205089008504980964603026955065146218281056;
    
    uint256 constant IC12x = 15353217144990262041216459957113650537647908543021525173461866511986941912973;
    uint256 constant IC12y = 2921045097328702981238681995018947852599543504705250076841449203830288504831;
    
    uint256 constant IC13x = 19632497433109874022088567339322324244713738979734687582748216888413034190347;
    uint256 constant IC13y = 15869223238436697701117321226669738445525953665077298498013127095893203873801;
    
    uint256 constant IC14x = 11447678290754612267763669620494277244026257901163522294889265338775902583559;
    uint256 constant IC14y = 5117501023601558757397159875149272645025642682921582965503197819030761790062;
    
    uint256 constant IC15x = 5529287439906811996958010420450660302770892143391186020353176141835413165064;
    uint256 constant IC15y = 11711216886403865794171602406925115903469001643895112766214626487484429215199;
    
    uint256 constant IC16x = 9078313962003814112357480694606571905620230651365266472730085045975268926181;
    uint256 constant IC16y = 9458967644778043826698859136439051695469136000378372872065671259671281646741;
    
    uint256 constant IC17x = 14464278332130394608377055315951326221142345700462005363656331664932195475731;
    uint256 constant IC17y = 16642050318706749883411104393344073212513931991050907624094314676407308628480;
    
    uint256 constant IC18x = 345940929409327116938641045805987158884951083108706107228053084646335025426;
    uint256 constant IC18y = 9861815476462221477558019703833598408544612346852031113986330364568745668285;
    
    uint256 constant IC19x = 16800586788222230457379402127528747251355279103857631176074611061447498996515;
    uint256 constant IC19y = 19756070509142155188961730791522319884193286213215413025690623520506675598242;
    
    uint256 constant IC20x = 21286132883747994902175101374835573371357422413357745639446538817622790157023;
    uint256 constant IC20y = 17578635197003378447511682024314086429343937894171592650991866862148242292488;
    
    uint256 constant IC21x = 20972858286370350470383134056893981539754190427253194841234362640984775679431;
    uint256 constant IC21y = 13707315383354815220094808138693641186264220214683709917664755586603951221144;
    
    uint256 constant IC22x = 16858833274988999610095646406713649503920383625723903443771539122459556336536;
    uint256 constant IC22y = 10620918323356704141432579782946555503736950197056401047919018497448267582514;
    
    uint256 constant IC23x = 10423980722067231692315156786808915589794197394357184075907592536303990967880;
    uint256 constant IC23y = 13159354260950091278075948894082470710432095067252302095059875109701483158065;
    
    uint256 constant IC24x = 542454961853785745329255689818403128148192338524344471032513711417025811526;
    uint256 constant IC24y = 21193322789591748102188796127401527547541250293057685346189759515800867919353;
    
    uint256 constant IC25x = 17364542024199549337835810419694313763334725732983072424732669175952795790494;
    uint256 constant IC25y = 8676742015698077816281339617131640835617782451702865846556307081622733438231;
    
    uint256 constant IC26x = 2431708649867631393481618026723344695879555921239076254748933549693564193977;
    uint256 constant IC26y = 20955702759596360135775277214483713877092516153520829943095338523870193836150;
    
    uint256 constant IC27x = 13911823614699359653434400096019459756165655041943106807164716167769955145275;
    uint256 constant IC27y = 17276549751893716798782596530460324720902431681305218090868337979334705667915;
    
    uint256 constant IC28x = 19590864365352262983196642562148512063740683170331803065927238023937439446482;
    uint256 constant IC28y = 17979196966946580050763471441858735408710496807739486683253349102914909652880;
    
    uint256 constant IC29x = 2410296104761859387564508307846781569289286972922020406739381612043052853349;
    uint256 constant IC29y = 15455454473843994115111534636645568267082885385768497484415173198206592007921;
    
    uint256 constant IC30x = 7535639797187628757705566478287088238018469809700533096910487841904055129650;
    uint256 constant IC30y = 16033709244895658645936172660840283227331788958912699860580793718447087127340;
    
    uint256 constant IC31x = 8857119696758856100514265918394623227135393212986276925667564217300421694337;
    uint256 constant IC31y = 11289585367225250234745450412397181767564282538088461985521586793450621944887;
    
    uint256 constant IC32x = 11268668876135298114345811474077063547334660038227581894982636475405068171429;
    uint256 constant IC32y = 12357054197828813277121807310093555768019861716369351209930979713748593260355;
    
    uint256 constant IC33x = 177178151555150259684556686860781610478246503559712429015144671328550294994;
    uint256 constant IC33y = 2363980775817605357764705700023797826553538627190682694017781427892692767134;
    
    uint256 constant IC34x = 16307918312114101893656936996001069063867437709572605573837391461245749036982;
    uint256 constant IC34y = 1219051159906190627684979939057004691926658222862421705588118945191068017607;
    
    uint256 constant IC35x = 5707570466996670449500678684423715352188026545950286844190089200574828319217;
    uint256 constant IC35y = 4179862208890538028327612174300503129595556451670258696031335251821805126775;
    
    uint256 constant IC36x = 14818149700686557843315923452763113138533265124518398647562537276104610798612;
    uint256 constant IC36y = 20859140882655469085274439105359936631927027329530356198527971611212869435319;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[36] calldata _pubSignals) public view returns (bool) {
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
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
